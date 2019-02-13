#pragma once

#include <functional>
#include <memory>

#include <uvw.hpp>

class TCPSession {
public:
    using malformed_data_cb = std::function<void()>;
    using got_dns_msg_cb = std::function<void(std::unique_ptr<char[]> data, size_t size)>;

    TCPSession(std::shared_ptr<uvw::TcpHandle> handle,
               malformed_data_cb malformed_data_handler,
               got_dns_msg_cb got_dns_msg_handler);
    virtual ~TCPSession();

    virtual void on_data_event(const char data[], size_t len);
    virtual void on_end_event();
    virtual void on_shutdown_event();

    virtual void write(std::unique_ptr<char[]> data, size_t len);

protected:
    virtual void receive_data(const char data[], size_t len);
    virtual void send_data(std::unique_ptr<char[]> data, size_t len);

private:
    std::string _buffer;
    std::shared_ptr<uvw::TcpHandle> _handle;
    malformed_data_cb _malformed_data;
    got_dns_msg_cb _got_dns_msg;
};
