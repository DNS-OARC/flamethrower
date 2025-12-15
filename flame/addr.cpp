// Copyright 2025 Flamethrower Contributors

#include "addr.h"

#include <arpa/inet.h>
#include <uv.h>

flame::socket_address::socket_address(const struct sockaddr &addr, socklen_t len)
    : socket_address()
{
    if (addr.sa_family == AF_UNSPEC) {
        return;
    }

    if ((addr.sa_family == AF_INET && len >= sizeof(sockaddr_in)) || (addr.sa_family == AF_INET6 && len >= sizeof(sockaddr_in6))) {
        memmove(&_addr, &addr, len);
        return;
    }

    throw unsupported_family();
}

std::string flame::socket_address::ip_str() const
{
    if (family() != AF_INET && family() != AF_INET6) {
        return "";
    }

    char buf[256] = {0};
    uv_ip_name(&sockaddr(), buf, sizeof(buf));

    return buf;
}

uint16_t flame::socket_address::port() const
{
    switch (family()) {
    case AF_INET:
        return htons(_addr.ipv4.sin_port);
    case AF_INET6:
        return htons(_addr.ipv6.sin6_port);
    default:
        return 0;
    }
}
