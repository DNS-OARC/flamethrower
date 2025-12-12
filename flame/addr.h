// Copyright 2025 Flamethrower Contributors

#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

#include <netinet/in.h>
#include <sys/socket.h>

namespace flame {

/**
 * socket_address is similar to sockaddr_storage but it can hold only AF_INET or AF_INET6 address.
 */
class socket_address
{
    union {
        sockaddr_in ipv4;
        sockaddr_in6 ipv6;
    } _addr;

    class unsupported_family : std::invalid_argument
    {
    public:
        unsupported_family()
            : std::invalid_argument("unsupported address family")
        {
        }
    };

public:
    socket_address()
        : _addr{}
    {
    }

    socket_address(const sockaddr &addr, socklen_t len);

    const struct sockaddr &sockaddr() const
    {
        return reinterpret_cast<const struct sockaddr &>(_addr);
    }

    struct sockaddr &sockaddr()
    {
        return reinterpret_cast<struct sockaddr &>(_addr);
    }

    operator struct sockaddr &()
    {
        return sockaddr();
    }

    operator const struct sockaddr &() const
    {
        return sockaddr();
    }

    socklen_t size()
    {
        switch (family()) {
        case AF_INET:
            return sizeof(struct sockaddr_in);
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
        default:
            return 0;
        }
    }

    static constexpr socklen_t capacity()
    {
        return sizeof(_addr);
    }

    int family() const
    {
        return sockaddr().sa_family;
    }

    std::string ip_str() const;
    uint16_t port() const;
};

} // namespace flame
