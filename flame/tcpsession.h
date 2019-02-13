#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <utility>

class TCPSession
{
public:
    using error_cb = std::function<void()>;
    using query_cb = std::function<void(std::unique_ptr<char[]> data, size_t size)>;

    void received(const char data[], size_t len)
    {
        buffer.append(data, len);

        while (try_yield_message()) {
        }
    }

    void on_error(error_cb handler)
    {
        error = std::move(handler);
    }

    void on_query(query_cb handler)
    {
        query = std::move(handler);
    }

private:
    bool try_yield_message()
    {
        const size_t MIN_DNS_QUERY_SIZE = 17;
        const size_t MAX_DNS_QUERY_SIZE = 512;

        std::uint16_t size = 0;

        if (buffer.size() < sizeof(size)) {
            return false;
        }

        // size is in network byte order.
        size = static_cast<unsigned char>(buffer[1]) |
               static_cast<unsigned char>(buffer[0]) << 8;

        if (size < MIN_DNS_QUERY_SIZE || size > MAX_DNS_QUERY_SIZE) {
            error();
            return false;
        }

        if (buffer.size() >= sizeof(size) + size) {
            auto data = std::make_unique<char[]>(size);
            memcpy(data.get(), buffer.data() + sizeof(size), size);
            buffer.erase(0, sizeof(size) + size);

            query(std::move(data), size);
            return true;
        }

        return false;
    }

    std::string buffer;
    error_cb error;
    query_cb query;
};
