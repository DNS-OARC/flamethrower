#include <iostream>
#include "quicsession.h"

QUICSession::QUICSession(std::shared_ptr<uvw::UDPHandle> handle,
        got_dns_msg_cb got_dns_msg_handler,
        conn_refused_cb conn_refused_handler,
        conn_error_cb conn_error_handler,
        stream_rst_cb stream_rst_handler,
        Target target,
        unsigned int port,
        int family,
        quicly_cid_plaintext_t cid)
    :_handle{handle},
    _got_dns_msg{std::move(got_dns_msg_handler)},
    _conn_refused{std::move(conn_refused_handler)},
    _conn_error{std::move(conn_error_handler)},
    _stream_rst{std::move(stream_rst_handler)},
    _target{target},
    _port{port},
    _family{family},
    _cid{cid}
{
    q_tlsctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites
    };
    q_stream_open = {{q_on_stream_open}, this};
    q_closed_by_remote = {{q_on_closed_by_remote}, this};
    q_ctx = quicly_spec_context;
    q_ctx.tls = &q_tlsctx;
    quicly_amend_ptls_context(q_ctx.tls);
    q_ctx.stream_open = (quicly_stream_open_t *) &q_stream_open;
    q_ctx.closed_by_remote =(quicly_closed_by_remote_t *) &q_closed_by_remote;

    _alpn = ptls_iovec_init("doq", 3);
    q_hand_prop = {0};
    q_hand_prop.client.negotiated_protocols.list = &_alpn;
    q_hand_prop.client.negotiated_protocols.count = 1;
}

QUICSession::~QUICSession()
{
}

quicly_stream_id_t QUICSession::write(std::unique_ptr<char[]> data, size_t len)
{
    int ret;
    if (!q_conn) {
        struct sockaddr_storage target_addr;
        target_addr.ss_family = _family;
        inet_pton(_family, _target.address.data(), ((sockaddr*)&target_addr)->sa_data);
        if ( (ret = quicly_connect(&q_conn, &q_ctx, _target.address.data(),
                        (struct sockaddr*)&target_addr, nullptr, &_cid,
                        ptls_iovec_init(nullptr, 0), &q_hand_prop, nullptr)) ){
            throw std::runtime_error("quicly connect failed: " + std::to_string(ret));
        }
    }

    quicly_stream_t *stream;
    
    if ( (ret = quicly_open_stream(q_conn, &stream, 0)) )
        throw std::runtime_error("quicly stream open failed: " + std::to_string(ret));
    quicly_stream_id_t id = stream->stream_id;

    /* write data to send buffer */
    quicly_streambuf_egress_write(stream, (void*)data.get(), len);
    quicly_streambuf_egress_shutdown(stream);
    // ???
    // in UDP, this buffer gets freed by libuv after send. in quic, it gets copied internally to
    // quic datagram, so this can be freed immediately

    return id;
}

void QUICSession::close()
{
    if (quicly_get_state(q_conn) == QUICLY_STATE_CONNECTED) {
        quicly_close(q_conn, 0, "No Error");
        send_pending();
    }
}

void QUICSession::receive_data(const char data[], size_t len, const uvw::Addr *src_addr)
{
    size_t off = 0;
    assert(q_conn);

    /* split UDP datagram into multiple QUIC packets */
    while (off < len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&q_ctx, &decoded, (uint8_t*) data, len, &off) == SIZE_MAX)
            break;
        /* TODO match incoming packets to connections, handle version negotiation, rebinding, retry, etc. */

        int ret;
        /* let the current connection handle ingress packets */
        sockaddr sa;
        if (_family == AF_INET) {
            uv_ip4_addr(src_addr->ip.data(), src_addr->port, (sockaddr_in *) &sa);
        } else {
            uv_ip6_addr(src_addr->ip.data(), src_addr->port, (sockaddr_in6 *) &sa);
        }
        ret = quicly_receive(q_conn, nullptr, &sa, &decoded);

        send_pending();
        if (ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED) {
            return;
        }

    }
}

void QUICSession::send_pending()
{
    if (!q_conn)
        return;
    quicly_address_t dest, src;
    struct iovec packets[10];
    uint8_t buf[10 * quicly_get_context(q_conn)->transport_params.max_udp_payload_size];
    size_t num_packets = 10;
    int ret;

    if ((ret = quicly_send(q_conn, &dest, &src, packets, &num_packets, buf, sizeof(buf))) == 0 && num_packets != 0) {

        switch (ret) {
            case 0:
                size_t i;
                for (i = 0; i != num_packets; ++i) {
                    // XXX libuv needs to own this since it frees async
                    char *data = (char*)std::malloc(packets[i].iov_len);
                    memcpy(data, packets[i].iov_base, packets[i].iov_len);
                    if (data == nullptr) {
                        throw std::runtime_error("unable to allocate datagram memory");
                    }
                    if (_family == AF_INET) {
                        _handle->send<uvw::IPv4>(_target.address, _port, data, packets[i].iov_len);
                    } else {
                        _handle->send<uvw::IPv6>(_target.address, _port, data, packets[i].iov_len);
                    }
                }
                break;
            case QUICLY_ERROR_FREE_CONNECTION:
                // connection is closed & free
                quicly_free(q_conn);
                q_conn = nullptr;
                break;
            default:
                _conn_error();
                throw std::runtime_error("quicly send failed: " + std::to_string(ret));
        }
    }
}

/*
 * Because only one query is sent per stream and the query is sent at
 * the same time the stream is opened, this should never happen.
 */
void q_on_stop_sending(quicly_stream_t *stream, int err)
{
    std::cerr << "QUIC unexpectedly received STOP_SENDING: " << PRIu16 << QUICLY_ERROR_GET_ERROR_CODE(err) << std::endl;
}

/*
 * Received in case of server-side sending error.
 */
void QUICSession::q_on_receive_reset(quicly_stream_t *stream, int err)
{
    custom_quicly_streambuf_t *sbuf = (custom_quicly_streambuf_t *) stream->data;
    QUICSession *ctx = (QUICSession *) sbuf->user_ctx;
    ctx->_stream_rst(stream->stream_id);
}

void QUICSession::q_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{

    custom_quicly_streambuf_t *sbuf = (custom_quicly_streambuf_t *) stream->data;
    QUICSession *ctx = (QUICSession *) sbuf->user_ctx;
    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return ;

    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        /* obtain contiguous bytes from the receive buffer */
        ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
        std::vector<char> msg((char *) input.base, (char *) (input.base+input.len));
        ctx->_got_dns_msg(msg, stream->stream_id);

        /* remove used bytes from receive buffer */
        quicly_streambuf_ingress_shift(stream, input.len);
    }
}

int QUICSession::q_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    custom_quicly_stream_open_t *self_ptr = (custom_quicly_stream_open_t *) self;
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit,
        q_on_stop_sending, q_on_receive, q_on_receive_reset};
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(custom_quicly_streambuf_t))) != 0)
        return ret;
    custom_quicly_streambuf_t *sbuf = (custom_quicly_streambuf_t *) stream->data;
    sbuf->user_ctx = self_ptr->user_ctx;

    stream->callbacks = &stream_callbacks;
    return 0;
}

void QUICSession::q_on_closed_by_remote(quicly_closed_by_remote_t *self, quicly_conn_t *conn, int err, uint64_t frame_type,
                                const char *reason, size_t reason_len)
{
    custom_quicly_closed_by_remote_t *self_ptr = (custom_quicly_closed_by_remote_t *) self;
    QUICSession *ctx = (QUICSession *) self_ptr->user_ctx;

    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        if (QUICLY_ERROR_GET_ERROR_CODE(err) == 0x2) {
            ctx->_conn_refused();
            return;
        } else {
            std::cerr << "transport close:code=0" << PRIx16 << QUICLY_ERROR_GET_ERROR_CODE(err) <<
               ";frame=" << PRIu64 << frame_type << ";reason=" << std::string(reason, reason_len) << std::endl;
        }
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        std::cerr << "application close:code=0" << PRIx16 << QUICLY_ERROR_GET_ERROR_CODE(err) <<
            ";reason=" << std::string(reason, reason_len) << std::endl;
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        std::cerr << "stateless reset" << std::endl;
    } else if (err == QUICLY_ERROR_NO_COMPATIBLE_VERSION) {
        std::cerr << "no compatible version" << std::endl;
    } else {
        std::cerr << "unexpected close:code=" << PRIu16 << err << std::endl;
    }

    ctx->_conn_error();
}
