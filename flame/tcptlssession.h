#pragma once

#include <gnutls/gnutls.h>

#include "tcpsession.h"

class TCPTLSSession : public TCPSession
{
public:
    using handshake_error_cb =  std::function<void()>;

    TCPTLSSession(std::shared_ptr<uvw::TcpHandle> handle,
                  TCPSession::malformed_data_cb malformed_data_handler,
                  TCPSession::got_dns_msg_cb got_dns_msg_handler,
                  TCPSession::connection_ready_cb connection_ready_handler,
                  handshake_error_cb handshake_error_handler);
    virtual ~TCPTLSSession();

    virtual bool setup();

    virtual void on_connect_event();

    virtual void close();
    virtual void receive_data(const char data[], size_t len);
    virtual void write(std::unique_ptr<char[]> data, size_t len);

    int gnutls_pull(void *buf, size_t len);
    int gnutls_push(const void *buf, size_t len);

protected:
    void do_handshake();

private:
    enum class LinkState { HANDSHAKE, DATA, CLOSE } _tls_state;
    handshake_error_cb _handshake_error;
    std::string _pull_buffer;

    gnutls_session_t _gnutls_session;
    gnutls_certificate_credentials_t _gnutls_cert_credentials;
};
