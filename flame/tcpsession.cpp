#include <cstdint>
#include <cstring>
#include <utility>

#include "tcpsession.h"

TCPSession::TCPSession(std::shared_ptr<uvw::TcpHandle> handle,
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

// remote peer closed connection, sent EOF
void TCPSession::on_end_event()
{
    _handle->shutdown();
}

// we've closed, send EOF
void TCPSession::on_shutdown_event()
{
    _handle->close();
}

// accumulate data and try to extract DNS messages
void TCPSession::receive_data(const char data[], size_t len)
{
    const size_t MIN_DNS_QUERY_SIZE = 17;
    const size_t MAX_DNS_QUERY_SIZE = 512;

    _buffer.append(data, len);

    for(;;) {
        std::uint16_t size;

        if (_buffer.size() < sizeof(size))
            break;

        // size is in network byte order.
        size = static_cast<unsigned char>(_buffer[1]) |
               static_cast<unsigned char>(_buffer[0]) << 8;

        if (size < MIN_DNS_QUERY_SIZE || size > MAX_DNS_QUERY_SIZE) {
            _malformed_data();
            break;
        }

        if (_buffer.size() >= sizeof(size) + size) {
            auto data = std::make_unique<char[]>(size);
            std::memcpy(data.get(), _buffer.data() + sizeof(size), size);
            _buffer.erase(0, sizeof(size) + size);
            _got_dns_msg(std::move(data), size);
        }
    }
}

// send data, giving data ownership to async library
void TCPSession::write(std::unique_ptr<char[]> data, size_t len)
{
    _handle->write(std::move(data), len);
}
