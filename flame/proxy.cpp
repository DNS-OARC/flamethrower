// Copyright 2025 Flamethrower Contributors

#include <cstring>
#include <stdexcept>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "proxy.h"
#include "utils.h"

ProxyInfo parse_proxy_spec(const std::string &spec, int family)
{
    ProxyInfo info{};
    info.enabled = true;

    auto parts = split(spec, '-');
    if (parts.size() != 2) {
        throw std::runtime_error("invalid proxy spec format: expecting SRC-DST");
    }

    auto parse_addr_port = [](const std::string &s, struct sockaddr_storage &ss, int hint_family) -> int {
        auto ap_parts = split(s, '#');
        std::string host;
        std::string port_str = "0";

        if (!ap_parts[0].empty() && ap_parts[0].front() == '[' && ap_parts[0].back() == ']') {
            host = ap_parts[0].substr(1, ap_parts[0].length() - 2);
        } else {
            host = ap_parts[0];
        }

        if (ap_parts.size() > 1) {
            port_str = ap_parts[1];
        }

        struct addrinfo hints;
        struct addrinfo *result;
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = hint_family;
        hints.ai_socktype = 0;

        int ret = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
        if (ret != 0) {
            throw std::runtime_error("getaddrinfo failed for " + host + ": " + gai_strerror(ret));
        }

        int resolved_family = 0;
        bool found = false;
        for (auto rp = result; rp != nullptr; rp = rp->ai_next) {
            if (hint_family == AF_UNSPEC || rp->ai_family == hint_family) {
                memcpy(&ss, rp->ai_addr, rp->ai_addrlen);
                resolved_family = rp->ai_family;
                found = true;
                break;
            }
        }

        freeaddrinfo(result);

        if (!found) {
            throw std::runtime_error("could not resolve address for the given family: " + host);
        }
        return resolved_family;
    };

    int src_family = parse_addr_port(parts[0], info.src_addr, family);
    int dst_family = parse_addr_port(parts[1], info.dst_addr, (family == AF_UNSPEC) ? src_family : family);

    if (src_family != dst_family) {
        throw std::runtime_error("proxy spec source and destination address families must match");
    }
    info.family = src_family;

    return info;
}

std::vector<char> generate_proxy_v2_header(const ProxyInfo &info, Protocol proto)
{
    if (info.family != AF_INET && info.family != AF_INET6) {
        throw std::runtime_error("unsupported address family for PROXY v2 header");
    }

    size_t addr_block_size = (info.family == AF_INET) ? 12 : 36;
    std::vector<char> header;
    header.reserve(16 + addr_block_size);

    const char signature[] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
    header.insert(header.end(), signature, signature + 12);

    header.push_back(0x21); // version 2, PROXY command

    uint8_t transport = 0;
    switch (proto) {
    case Protocol::UDP:
        transport = 0x02; // DGRAM
        break;
    case Protocol::TCP:
    case Protocol::DOT:
#ifdef DOH_ENABLE
    case Protocol::DOH:
#endif
        transport = 0x01; // STREAM
        break;
    }

    uint8_t family_proto;
    if (info.family == AF_INET) {
        family_proto = 0x10 | transport; // AF_INET
    } else {
        family_proto = 0x20 | transport; // AF_INET6
    }
    header.push_back(static_cast<char>(family_proto));

    uint16_t addr_len_n = htons(static_cast<uint16_t>(addr_block_size));
    header.insert(header.end(),
        reinterpret_cast<const char *>(&addr_len_n),
        reinterpret_cast<const char *>(&addr_len_n) + 2);

    auto append = [&header](const void *src, size_t len) {
        auto *p = reinterpret_cast<const char *>(src);
        header.insert(header.end(), p, p + len);
    };

    if (info.family == AF_INET) {
        auto *src_sin = reinterpret_cast<const struct sockaddr_in *>(&info.src_addr);
        auto *dst_sin = reinterpret_cast<const struct sockaddr_in *>(&info.dst_addr);
        append(&src_sin->sin_addr, 4);
        append(&dst_sin->sin_addr, 4);
        append(&src_sin->sin_port, 2);
        append(&dst_sin->sin_port, 2);
    } else {
        auto *src_sin6 = reinterpret_cast<const struct sockaddr_in6 *>(&info.src_addr);
        auto *dst_sin6 = reinterpret_cast<const struct sockaddr_in6 *>(&info.dst_addr);
        append(&src_sin6->sin6_addr, 16);
        append(&dst_sin6->sin6_addr, 16);
        append(&src_sin6->sin6_port, 2);
        append(&dst_sin6->sin6_port, 2);
    }

    return header;
}
