#include <cstdint>
#include <cstring>
#include <utility>

#include "tcpsession.h"

TCPSession::TCPSession(std::shared_ptr<uvw::TCPHandle> handle,
                       malformed_data_cb malformed_data_handler,
                       got_dns_msg_cb got_dns_msg_handler,
                       connection_ready_cb connection_ready_handler)
    : _handle{handle},
      _malformed_data{std::move(malformed_data_handler)},
      _got_dns_msg{std::move(got_dns_msg_handler)},
      _connection_ready{std::move(connection_ready_handler)}
{
}

TCPSession::~TCPSession()
{
}

// do any pre-connection setup, return true if all OK.
bool TCPSession::setup()
{
    return true;
}

void TCPSession::on_connect_event()
{
    _connection_ready();
}

// remote peer closed connection
void TCPSession::on_end_event()
{
    _handle->close();
}

// all local writes now finished
void TCPSession::on_shutdown_event()
{
    _handle->close();
}

// gracefully terminate the session
void TCPSession::close()
{
    _handle->stop();
    _handle->shutdown();
}

// accumulate data and try to extract DNS messages
void TCPSession::receive_data(const char data[], size_t len)
{
    // dnsheader is 12, at least one byte for the minimum name,
    // two bytes for the qtype and another two for the qclass
    const size_t MIN_DNS_RESPONSE_SIZE = 17;

    _buffer.append(data, len);

    for(;;) {
        std::uint16_t size;

        if (_buffer.size() < sizeof(size))
            break;

        // size is in network byte order.
        size = static_cast<unsigned char>(_buffer[1]) |
               static_cast<unsigned char>(_buffer[0]) << 8;

        // no need to check the maximum size here since the maximum size
        // that a std::uint16t_t can hold, std::numeric_limits<std::uint16_t>::max()
        // (65535 bytes) is allowed over TCP
        if (size < MIN_DNS_RESPONSE_SIZE) {
            _malformed_data();
            break;
        }

        if (_buffer.size() >= sizeof(size) + size) {
            auto data = std::make_unique<char[]>(size);
            std::memcpy(data.get(), _buffer.data() + sizeof(size), size);
            _buffer.erase(0, sizeof(size) + size);
            _got_dns_msg(std::move(data), size);
        } else {
            // Nope, we need more data.
            break;
        }
    }
}

// send data, giving data ownership to async library
void TCPSession::write(std::unique_ptr<char[]> data, size_t len)
{
    _handle->write(std::move(data), len);
}
