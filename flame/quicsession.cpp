#include <iostream>
#include <unistd.h>
#include "quicsession.h"

QUICSession::QUICSession(std::shared_ptr<uvw::UDPHandle> handle,
        got_dns_msg_cb got_dns_msg_handler,
        conn_refused_cb conn_refused_handler,
        conn_error_cb conn_error_handler,
        stream_rst_cb stream_rst_handler,
        Target target,
        unsigned int port,
        int family,
        connection_id_t cid)
    :_handle{handle},
    _got_dns_msg{std::move(got_dns_msg_handler)},
    _conn_refused{std::move(conn_refused_handler)},
    _conn_error{std::move(conn_error_handler)},
    _stream_rst{std::move(stream_rst_handler)},
    _target{target},
    _port{port},
    _family{family},
    _cid{(quicly_cid_plaintext_t) cid}
{
    _q_tlsctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites
    };
    _q_stream_open = {{q_on_stream_open}, this};
    _q_closed_by_remote = {{q_on_closed_by_remote}, this};
    _q_ctx = quicly_spec_context;
    _q_ctx.tls = &_q_tlsctx;
    quicly_amend_ptls_context(_q_ctx.tls);
    _q_ctx.stream_open = (quicly_stream_open_t *) &_q_stream_open;
    _q_ctx.closed_by_remote =(quicly_closed_by_remote_t *) &_q_closed_by_remote;

    _alpn = ptls_iovec_init("doq-i03", 7);
    _q_hand_prop = {0};
    _q_hand_prop.client.negotiated_protocols.list = &_alpn;
    _q_hand_prop.client.negotiated_protocols.count = 1;
}

QUICSession::~QUICSession()
{
}

connection_id_t new_connection_id(){
    connection_id_t cid = {0, 0, 0, 0};
    return cid;
}

connection_id_t next_connection_id(connection_id_t id){
    ++id.master_id;
    return id;
}

stream_id_t QUICSession::write(std::unique_ptr<char[]> data, size_t len)
{
    int ret;
    if (!_q_conn) {
        struct sockaddr_storage target_addr;
        target_addr.ss_family = _family;
        inet_pton(_family, _target.address.data(), ((sockaddr*)&target_addr)->sa_data);
        if ( (ret = quicly_connect(&_q_conn, &_q_ctx, _target.address.data(),
                        (struct sockaddr*)&target_addr, nullptr, &_cid,
                        ptls_iovec_init(nullptr, 0), &_q_hand_prop, nullptr)) ){
            throw std::runtime_error("quicly connect failed: " + std::to_string(ret));
        }
    }

    quicly_stream_t *stream;
    
    if ( (ret = quicly_open_stream(_q_conn, &stream, 0)) )
        throw std::runtime_error("quicly stream open failed: " + std::to_string(ret));
    quicly_stream_id_t id = stream->stream_id;

    // write data to send buffer
    quicly_streambuf_egress_write(stream, (void*)data.get(), len);
    quicly_streambuf_egress_shutdown(stream);

    return (stream_id_t) id;
}

void QUICSession::close()
{
    if (_q_conn) {
        quicly_close(_q_conn, 0, "No Error");
        send_pending();
        //free the conn if it wasn't already done by send_pending
        if (_q_conn) {
            quicly_free(_q_conn);
            _q_conn = nullptr;
        }
    }
}

void QUICSession::receive_data(const char data[], size_t len, const uvw::Addr *src_addr)
{
    size_t off = 0;
    if (!_q_conn)
        return;

    // split UDP datagram into multiple QUIC packets
    while (off < len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&_q_ctx, &decoded, (uint8_t*) data, len, &off) == SIZE_MAX)
            break;

        int ret;
        // let the current connection handle ingress packets
        sockaddr_storage sa;
        if (_family == AF_INET)
            uv_ip4_addr(src_addr->ip.data(), src_addr->port, (sockaddr_in *) &sa);
        else
            uv_ip6_addr(src_addr->ip.data(), src_addr->port, (sockaddr_in6 *) &sa);

        ret = quicly_receive(_q_conn, nullptr, (sockaddr *) &sa, &decoded);

        if (ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED)
            return;

    }
    send_pending();
}

void QUICSession::send_pending()
{
    if (!_q_conn)
        return;
    quicly_address_t dest, src;
    struct iovec packets[10];
    uint8_t buf[10 * quicly_get_context(_q_conn)->transport_params.max_udp_payload_size];
    size_t num_packets = 10;
    int ret;

    switch ((ret = quicly_send(_q_conn, &dest, &src, packets, &num_packets, buf, sizeof(buf)))) {
        case 0:
            for (size_t i = 0; i < num_packets; ++i) {
                // libuv needs to own this in an unique_ptr since it frees async
                std::unique_ptr<char[]> data{new char[packets[i].iov_len]};
                memcpy(data.get(), packets[i].iov_base, packets[i].iov_len);
                _handle->send(_target.address, _port, std::move(data), packets[i].iov_len);
            }
            break;
        case QUICLY_ERROR_FREE_CONNECTION:
            // connection is closed & free
            quicly_free(_q_conn);
            _q_conn = nullptr;
            break;
        default:
            _conn_error();
            throw std::runtime_error("quicly send failed: " + std::to_string(ret));
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
    ctx->_stream_rst((stream_id_t) stream->stream_id);
}

void QUICSession::q_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{

    custom_quicly_streambuf_t *sbuf = (custom_quicly_streambuf_t *) stream->data;
    QUICSession *ctx = (QUICSession *) sbuf->user_ctx;
    // read input to receive buffer
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return ;

    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        // obtain contiguous bytes from the receive buffer
        ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

        std::uint16_t size = static_cast<unsigned char>(input.base[1]) |
                             static_cast<unsigned char>(input.base[0]) << 8;
        if (size != input.len - 2)
            ctx->_conn_error();

        std::vector<char> msg((char *) (input.base + 2), (char *) (input.base+input.len));
        ctx->_got_dns_msg(msg, (stream_id_t) stream->stream_id);

        // remove used bytes from receive buffer
        quicly_streambuf_ingress_shift(stream, input.len);
        //close the connection on the last opened stream
        if (quicly_num_streams(stream->conn) <= 1)
            quicly_close(stream->conn, 0, "No Error");
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
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        std::cerr << "no compatible version" << std::endl;
    } else {
        std::cerr << "unexpected close:code=" << PRIu16 << err << std::endl;
    }

    ctx->_conn_error();
}
