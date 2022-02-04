#pragma once

#include <functional>
#include <memory>

#include <uvw.hpp>

class TCPSession {
public:
    using malformed_data_cb = std::function<void()>;
    using got_dns_msg_cb = std::function<void(std::unique_ptr<char[]> data, size_t size)>;
    using connection_ready_cb = std::function<void()>;

    TCPSession(std::shared_ptr<uvw::TCPHandle> handle,
               malformed_data_cb malformed_data_handler,
               got_dns_msg_cb got_dns_msg_handler,
               connection_ready_cb connection_ready_handler);
    virtual ~TCPSession();

    virtual bool setup();

    virtual void on_connect_event();
    virtual void on_end_event();
    virtual void on_shutdown_event();

    virtual void close();
    virtual void receive_data(const char data[], size_t len);
    virtual void write(std::unique_ptr<char[]> data, size_t len);

private:
    std::string _buffer;
    std::shared_ptr<uvw::TCPHandle> _handle;
    malformed_data_cb _malformed_data;
    got_dns_msg_cb _got_dns_msg;
    connection_ready_cb _connection_ready;
};
