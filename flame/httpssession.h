#pragma once

#include <gnutls/gnutls.h>
#include <nghttp2/nghttp2.h>
#include <url_parser.h>

#include "base64.h"
#include "tcpsession.h"
#include "http.h"
#include "target.h"

struct http2_stream_data {
    http2_stream_data(std::string _scheme, std::string _authority, std::string _path, int32_t _stream_id, std::string _data):
	scheme(_scheme), authority(_authority), path(_path), stream_id(_stream_id), data(_data) {}
    std::string scheme;
    std::string authority;
    std::string path;
    int32_t stream_id;
    int32_t id;
    std::string data;
}; 

class HTTPSSession : public TCPSession
{
public:
    using log_send_cb = std::function<void(int32_t id)>;
    using handshake_error_cb =  std::function<void()>;

    HTTPSSession(std::shared_ptr<uvw::TcpHandle> handle,
		 TCPSession::malformed_data_cb malformed_data_handler,
		 TCPSession::got_dns_msg_cb got_dns_msg_handler,
		 TCPSession::connection_ready_cb connection_ready_handler,
		 handshake_error_cb handshake_error_handler,
		 Target target,
		 HTTPMethod method);
    virtual ~HTTPSSession();

    virtual bool setup();

    virtual void on_connect_event();

    void send_tls(void* data, size_t len);
    void init_nghttp2();
    void send_settings();
    void receive_response(const char data[], size_t len);
    int session_send();
    int session_receive();

    virtual void close();
    virtual void receive_data(const char data[], size_t len);
    virtual void write(std::unique_ptr<char[]> data, size_t len);
    void process_receive(const uint8_t *data, size_t len);

    int gnutls_pull(void *buf, size_t len);
    int gnutls_push(const void *buf, size_t len);

    http2_stream_data* create_http2_stream_data(std::unique_ptr<char[]> data, size_t len);
    void add_stream(http2_stream_data *stream_data);
    void remove_stream(http2_stream_data *stream_data); 

protected:
    void destroy_stream();
    void destroy_session();
    void do_handshake();

private:
    malformed_data_cb _malformed_data;
    got_dns_msg_cb _got_dns_msg;
    std::shared_ptr<uvw::TcpHandle> _handle;
    enum class LinkState { HANDSHAKE, DATA, CLOSE } _tls_state;
    handshake_error_cb _handshake_error;
    Target _target;
    HTTPMethod _method;

    nghttp2_session* _current_session;
    std::string _pull_buffer;

    gnutls_session_t _gnutls_session;
    gnutls_certificate_credentials_t _gnutls_cert_credentials;
};
