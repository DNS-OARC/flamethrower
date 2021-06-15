#pragma once

#include <functional>
#include <memory>

#include <uvw.hpp>
#include <picotls.h>
#include <picotls/openssl.h>
#include <quicly/defaults.h>
#include "quicly/streambuf.h"

#include "target.h"

typedef struct {
    quicly_stream_open_t stream_open;
    void *user_ctx;
} custom_quicly_stream_open_t;

typedef struct {
    quicly_streambuf_t sb;
    void *user_ctx;
} custom_quicly_streambuf_t;

typedef struct {
    quicly_closed_by_remote_t closed_by;
    void *user_ctx;
} custom_quicly_closed_by_remote_t;

class QUICSession {
public:
    using conn_refused_cb = std::function<void()>;
    using conn_error_cb = std::function<void()>;
    using stream_rst_cb = std::function<void(quicly_stream_id_t id)>;
    using got_dns_msg_cb = std::function<void(std::unique_ptr<char[]> data, size_t size, quicly_stream_id_t id)>;

    QUICSession(std::shared_ptr<uvw::UDPHandle> handle,
            got_dns_msg_cb got_dns_msg_handler,
            conn_refused_cb conn_refused_handler,
            conn_error_cb conn_error_handler,
            stream_rst_cb stream_rst_handler,
            Target target,
            unsigned int port,
            int family,
            quicly_cid_plaintext_t cid);
    virtual ~QUICSession();

    virtual void close();
    virtual void receive_data(const char data[], size_t len, const uvw::Addr *src_addr);
    /*
     * Writes the data in a new stream, but does not send it yet.
     * Implicitly opens a new quic connection if necessary.
     * Returns the stream_id of the opened stream carying the query.
     */
    virtual quicly_stream_id_t write(std::unique_ptr<char[]> data, size_t len);

    void send_pending();

private:

    static void q_on_receive_reset(quicly_stream_t *stream, int err);
    static void q_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
    static int q_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
    static void q_on_closed_by_remote(quicly_closed_by_remote_t *self, quicly_conn_t *conn, int err, uint64_t frame_type, const char *reason, size_t reason_len);

    std::shared_ptr<uvw::UDPHandle> _handle;
    got_dns_msg_cb _got_dns_msg;
    conn_refused_cb _conn_refused;
    conn_error_cb _conn_error;
    stream_rst_cb _stream_rst;

    Target _target;
    unsigned int _port;
    int _family;

    //tells the negotiated protocol
    ptls_iovec_t _alpn;
    quicly_conn_t *q_conn;
    //stores the cid for the next connection
    quicly_cid_plaintext_t _cid;
    ptls_handshake_properties_t q_hand_prop;
    custom_quicly_stream_open_t q_stream_open;
    custom_quicly_closed_by_remote_t q_closed_by_remote;
    quicly_context_t q_ctx;
    ptls_context_t q_tlsctx;
};
