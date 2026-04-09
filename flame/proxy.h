// Copyright 2025 Flamethrower Contributors

#pragma once

#include <string>
#include <vector>

#include <sys/socket.h>

#include "protocol.h"

struct ProxyInfo {
    bool enabled = false;
    struct sockaddr_storage src_addr{};
    struct sockaddr_storage dst_addr{};
    int family{};
};

// Parse the proxy spec string: SRC_ADDR[#SRC_PORT]-DST_ADDR[#DST_PORT]
// family can be AF_INET, AF_INET6, or AF_UNSPEC (auto-detect from addresses)
ProxyInfo parse_proxy_spec(const std::string &spec, int family);

// Generate a PROXY protocol v2 header
std::vector<char> generate_proxy_v2_header(const ProxyInfo &info, Protocol proto);
