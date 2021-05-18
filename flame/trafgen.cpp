// Copyright 2017-2019 NSONE, Inc

#include <algorithm>
#include <iostream>
#include <memory>
#include <random>
#include <string>

#include "trafgen.h"
#include "tcptlssession.h"

#ifdef QUIC_ENABLE
#include <picotls.h>
#include <picotls/openssl.h>
#include <quicly/defaults.h>
#endif

TrafGen::TrafGen(std::shared_ptr<uvw::Loop> l,
    std::shared_ptr<Metrics> s,
    std::shared_ptr<Config> c,
    std::shared_ptr<TrafGenConfig> tgc,
    std::shared_ptr<QueryGenerator> q,
    std::shared_ptr<TokenBucket> r)
    : _loop(l)
    , _metrics(s)
    , _config(c)
    , _traf_config(tgc)
    , _qgen(q)
    , _rate_limit(r)
    , _stopping(false)
{
    // build a list of random ids we will use for queries
    std::random_device rd;
    std::mt19937 g(rd());

#ifdef QUIC_ENABLE
    if (_traf_config->protocol == Protocol::QUIC) {
        // same max as below, to mimic the behavior of the other protocols,
        // even if the streams_id use an uint64_t
        _open_streams.reserve(std::numeric_limits<uint16_t>::max());
    } else
#endif
    {
        for (uint16_t i = 0; i < std::numeric_limits<uint16_t>::max(); i++)
            _free_id_list.push_back(i);
        std::shuffle(_free_id_list.begin(), _free_id_list.end(), g);
        // allocate enough space for the amount of queries we expect to have in flight
        // max here is based on uint16, the number of ids
        _in_flight.reserve(std::numeric_limits<uint16_t>::max());
    }
}

void TrafGen::process_wire(const char data[], size_t len)
{

    if (len <= 12) {
        _metrics->bad_receive(_in_flight.size());
        return;
    }

    // The first 2 bytes are the query ID.
    u_int16_t id = ntohs(*(u_int16_t *)data);
    // The response code is in the low-order 4 bits of the flags header field.
    uint8_t rcode = data[3] & 0xf;

    if (_in_flight.find(id) == _in_flight.end()) {
        if (_config->verbosity() > 1) {
            std::cerr << "untracked " << id << std::endl;
        }
        _metrics->bad_receive(_in_flight.size());
        return;
    }

    _metrics->receive(_in_flight[id].send_time, rcode, _in_flight.size());
    _in_flight.erase(id);
    _free_id_list.push_back(id);

}

void TrafGen::start_udp()
{

    _udp_handle = _loop->resource<uvw::UDPHandle>(_traf_config->family);

    _udp_handle->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent &e, uvw::UDPHandle &) {
        if (0 == strcmp(e.name(), "EADDRNOTAVAIL"))
            throw std::runtime_error("unable to bind to ip address: " + _traf_config->bind_ip);
        _metrics->net_error();
    });

    if (_traf_config->family == AF_INET) {
        _udp_handle->bind<uvw::IPv4>(_traf_config->bind_ip, 0);
    } else {
        _udp_handle->bind<uvw::IPv6>(_traf_config->bind_ip, 0, uvw::UDPHandle::Bind::IPV6ONLY);
    }

    _metrics->trafgen_id(_udp_handle->sock().port);

    _udp_handle->on<uvw::UDPDataEvent>([this](const uvw::UDPDataEvent &event, uvw::UDPHandle &h) {
        process_wire(event.data.get(), event.length);
    });

    _udp_handle->recv();
}

void TrafGen::start_tcp_session()
{

    assert(_tcp_handle.get() == 0);
    assert(_tcp_session.get() == 0);
    assert(_finish_session_timer.get() == 0);
    Target current_target = _traf_config->next_target();
    _tcp_handle = _loop->resource<uvw::TcpHandle>(_traf_config->family);

    if (_traf_config->family == AF_INET) {
        _tcp_handle->bind<uvw::IPv4>(_traf_config->bind_ip, 0);
    } else {
        _tcp_handle->bind<uvw::IPv6>(_traf_config->bind_ip, 0, uvw::TcpHandle::Bind::IPV6ONLY);
    }

    _metrics->trafgen_id(_tcp_handle->sock().port);

    auto malformed_data = [this]() {
        _metrics->net_error();
        handle_timeouts(true);
        _tcp_handle->close();
    };
    auto got_dns_message = [this](std::unique_ptr<const char[]> data,
                                  size_t size) {
        process_wire(data.get(), size);
    };
    auto connection_ready = [this]() {
        /** SEND DATA **/
        uint16_t id{0};
        std::vector<uint16_t> id_list;
        for (int i = 0; i < _traf_config->batch_count; i++) {
            if (_free_id_list.empty()) {
                // out of ids, have to limit
                break;
            }
            if (_rate_limit && !_rate_limit->consume(1, this->_loop->now()))
                break;
            id = _free_id_list.back();
            _free_id_list.pop_back();
            assert(_in_flight.find(id) == _in_flight.end());
            id_list.push_back(id);
            // might be better to do this after write (in WriteEvent) but it needs to be available
            // by the time DataEvent fires, and we don't want a race there
            _in_flight[id].send_time = std::chrono::high_resolution_clock::now();

#ifdef DOH_ENABLE
            // Send one by one with DoH
            if(_traf_config->protocol == Protocol::DOH) {
                auto qt = (_traf_config->method == HTTPMethod::GET)
                    ? _qgen->next_base64url(id_list[i])
                    : _qgen->next_udp(id_list[i]);
                _tcp_session->write(std::move(std::get<0>(qt)), std::get<1>(qt));
                _metrics->send(std::get<1>(qt), 1, _in_flight.size());
            }
#endif
        }

        if (id_list.size() == 0) {
            // didn't send anything, probably due to rate limit. close.
            _tcp_handle->close();
            return;
        }

#ifdef DOH_ENABLE
        if(_traf_config->protocol != Protocol::DOH) {
#endif
            auto qt = _qgen->next_tcp(id_list);

            // async send the batch. fires WriteEvent when finished sending.
            _tcp_session->write(std::move(std::get<0>(qt)), std::get<1>(qt));

            _metrics->send(std::get<1>(qt), id_list.size(), _in_flight.size());
#ifdef DOH_ENABLE
        }
#endif
    };

    // For now, treat a TLS handshake failure as malformed data
    if(_traf_config->protocol == Protocol::TCP) {
        _tcp_session = std::make_shared<TCPSession>(_tcp_handle, malformed_data, got_dns_message, connection_ready);
    } else if(_traf_config->protocol == Protocol::DOT) {
        _tcp_session = std::make_shared<TCPTLSSession>(_tcp_handle, malformed_data, got_dns_message, connection_ready, malformed_data);
    } 
#ifdef DOH_ENABLE
	else {
        _tcp_session = std::make_shared<HTTPSSession>(_tcp_handle, malformed_data, got_dns_message, connection_ready, malformed_data, current_target, _traf_config->method);
    }
#endif
    if (!_tcp_session->setup()) {
        return;
    }

    /** SOCKET CALLBACKS **/

    // SOCKET: local socket was closed, cleanup resources and possibly restart another connection
    _tcp_handle->on<uvw::CloseEvent>([this](uvw::CloseEvent &event, uvw::TcpHandle &h) {
        // if timer is still going (e.g. we got here through EndEvent), cancel it
        if (_finish_session_timer.get()) {
            _finish_session_timer->stop();
            _finish_session_timer->close();
        }
        if (_tcp_handle.get()) {
            _tcp_handle->stop();
        }
        _tcp_session.reset();
        _tcp_handle.reset();
        _finish_session_timer.reset();
        handle_timeouts(true);
        if (!_stopping) {
            start_tcp_session();
        }
    });

    // SOCKET: socket error
    _tcp_handle->on<uvw::ErrorEvent>([this](uvw::ErrorEvent &event, uvw::TcpHandle &h) {
        _metrics->net_error();
        // XXX need to close?
    });

    // INCOMING: remote peer closed connection, EOF
    _tcp_handle->on<uvw::EndEvent>([this](uvw::EndEvent &event, uvw::TcpHandle &h) {
        _tcp_session->on_end_event();
    });

    // OUTGOING: we've finished writing all our data and are shutting down
    _tcp_handle->on<uvw::ShutdownEvent>([this](uvw::ShutdownEvent &event, uvw::TcpHandle &h) {
        _tcp_session->on_shutdown_event();
    });

    // INCOMING: remote peer sends data, pass to session
    _tcp_handle->on<uvw::DataEvent>([this](uvw::DataEvent &event, uvw::TcpHandle &h) {
        _tcp_session->receive_data(event.data.get(), event.length);
    });

    // OUTGOING: write operation has finished
    _tcp_handle->on<uvw::WriteEvent>([this](uvw::WriteEvent &event, uvw::TcpHandle &h) {
        if (!_finish_session_timer)
            start_wait_timer_for_session_finish();
    });

    // SOCKET: on connect
    _tcp_handle->on<uvw::ConnectEvent>([this](uvw::ConnectEvent &event, uvw::TcpHandle &h) {
        _tcp_session->on_connect_event();
        _metrics->tcp_connection();

        // start reading from incoming stream, fires DataEvent when receiving
        _tcp_handle->read();
    });

    // fires ConnectEvent when connected
    if (_traf_config->family == AF_INET) {
        _tcp_handle->connect<uvw::IPv4>(current_target.address, _traf_config->port);
    } else {
        _tcp_handle->connect<uvw::IPv6>(current_target.address, _traf_config->port);
    }
}

void TrafGen::start_wait_timer_for_session_finish()
{

    // wait for all responses, but no longer than query timeout
    // once we have all responses, or timed out, delay for delay time, then start over
    auto wait_time_start = std::chrono::high_resolution_clock::now();
    assert(_finish_session_timer.get() == 0);
    _finish_session_timer = _loop->resource<uvw::TimerHandle>();
    _finish_session_timer->on<uvw::TimerEvent>([this, wait_time_start](const uvw::TimerEvent &event,
                                                   uvw::TimerHandle &h) {
        auto now = std::chrono::high_resolution_clock::now();
        auto cur_wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - wait_time_start).count();

        if ((_in_flight.size() || _open_streams.size()) && (cur_wait_ms < (_traf_config->r_timeout * 1000))) {
            // queries in flight and timeout time not elapsed, still wait
            return;
        } else if (cur_wait_ms < (_traf_config->s_delay)) {
            // either timed out or nothing in flight. ensure delay period has passed
            // before restarting
            return;
        }

        // shut down timer and connection. TCP CloseEvent will handle restarting sends.
        _finish_session_timer->stop();
        _finish_session_timer->close();

#ifdef QUIC_ENABLE
        if (_traf_config->protocol == Protocol::QUIC) {
            quicly_close(q_conn, 0, "");
            send_pending(q_conn);
            quic_send();
        } else
#endif
            _tcp_handle->close();
    });
    _finish_session_timer->start(uvw::TimerHandle::Time{1}, uvw::TimerHandle::Time{50});
}

#ifdef QUIC_ENABLE

int TrafGen::send_pending(quicly_conn_t *conn)
{
    quicly_address_t dest, src;
    struct iovec packets[10];
    uint8_t buf[10 * quicly_get_context(conn)->transport_params.max_udp_payload_size];
    size_t num_packets = 10;
    int ret;

    if ((ret = quicly_send(conn, &dest, &src, packets, &num_packets, buf, sizeof(buf))) == 0 && num_packets != 0) {

        switch (ret) {
            case 0: {
                        size_t i;
                        for (i = 0; i != num_packets; ++i) {
                            // XXX libuv needs to own this since it frees async
                            char *data = (char*)std::malloc(packets[i].iov_len);
                            memcpy(data, packets[i].iov_base, packets[i].iov_len);
                            if (data == nullptr) {
                                throw std::runtime_error("unable to allocate datagram memory");
                            }
                            if (_traf_config->family == AF_INET) {
                                _udp_handle->send<uvw::IPv4>(_traf_config->next_target().address, _traf_config->port, data, packets[i].iov_len);
                            } else {
                                _udp_handle->send<uvw::IPv6>(_traf_config->next_target().address, _traf_config->port, data, packets[i].iov_len);
                            }
                        }
                    } break;
            case QUICLY_ERROR_FREE_CONNECTION:
                    // connection is closed & free
                    quicly_free(conn);
                    conn = nullptr;
                    return ret;
            default:
                    std::cerr << "quicly_send returned" << std::endl;
                    return ret;
        }
    }
    return ret;
}

void TrafGen::quic_send()
{

    if (_udp_handle.get() && !_udp_handle->active())
        return;
    if (_qgen->finished())
        return;
    int ret;
    if (q_conn != nullptr) {
        quicly_close(q_conn, 0, "");
        send_pending(q_conn);
    }
    _finish_session_timer.reset();

    if ((ret = quicly_connect(&q_conn, &q_ctx, target_name.data(),
                    (struct sockaddr*)&target_addr, nullptr, &q_next_cid,
                    ptls_iovec_init(nullptr, 0), &q_hand_prop, nullptr)) != 0) {
        throw std::runtime_error("quicly connect failed: " + std::to_string(ret));
    }
    ++q_next_cid.master_id;

    printf("cid\'s: %d %d %d %d\n", q_next_cid.master_id, q_next_cid.path_id, q_next_cid.thread_id, q_next_cid.node_id); 

    quicly_stream_id_t id{0};
    for (int i = 0; i < _traf_config->batch_count; i++) {
        if (_open_streams.size() == std::numeric_limits<uint16_t>::max()) {
            std::cerr << "max in flight reached" << std::endl;
            return;
        }
        if (_rate_limit && !_rate_limit->consume(1, this->_loop->now()))
            return;
        //in doq, all dns messages ID are set to 0
        auto qt = _qgen->next_udp(0);

        quicly_stream_t *stream; /* we retain the opened stream via the on_stream_open callback */
        quicly_open_stream(q_conn, &stream, 0);
        if (!quicly_sendstate_is_open(&stream->sendstate))
            return;
        id = stream->stream_id;

        /* write data to send buffer */
        quicly_streambuf_egress_write(stream, (void*)std::get<0>(qt).get(), std::get<1>(qt));
        quicly_streambuf_egress_shutdown(stream);
        // ???
        // in UDP, this buffer gets freed by libuv after send. in quic, it gets copied internally to
        // quic datagram, so this can be freed immediately

        _metrics->send(std::get<1>(qt), 1, _open_streams.size());
        _open_streams[id].send_time = std::chrono::high_resolution_clock::now();
    }

    send_pending(q_conn);
    start_wait_timer_for_session_finish();

}
#endif

void TrafGen::udp_send()
{

    if (_udp_handle.get() && !_udp_handle->active())
        return;
    if (_qgen->finished())
        return;
    if (_free_id_list.size() == 0) {
        std::cerr << "max in flight reached" << std::endl;
        return;
    }
    uint16_t id{0};
    for (int i = 0; i < _traf_config->batch_count; i++) {
        if (_rate_limit && !_rate_limit->consume(1, _loop->now()))
            return;
        if (_free_id_list.size() == 0) {
            std::cerr << "max in flight reached" << std::endl;
            return;
        }
        id = _free_id_list.back();
        _free_id_list.pop_back();
        assert(_in_flight.find(id) == _in_flight.end());
        auto qt = _qgen->next_udp(id);
        if (_traf_config->family == AF_INET) {
            _udp_handle->send<uvw::IPv4>(_traf_config->next_target().address, _traf_config->port,
                std::move(std::get<0>(qt)),
                std::get<1>(qt));
        } else {
            _udp_handle->send<uvw::IPv6>(_traf_config->next_target().address, _traf_config->port,
                std::move(std::get<0>(qt)),
                std::get<1>(qt));
        }
        _metrics->send(std::get<1>(qt), 1, _in_flight.size());
        _in_flight[id].send_time = std::chrono::high_resolution_clock::now();
    }
}

#ifdef QUIC_ENABLE
static void q_on_stop_sending(quicly_stream_t *stream, int err)
{
    std::cerr << "QUIC received STOP_SENDING: " << PRIu16 << "\n" << QUICLY_ERROR_GET_ERROR_CODE(err) << std::endl;
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

static void q_on_receive_reset(quicly_stream_t *stream, int err)
{
    std::cerr << "QUIC received RESET_STREAM: " << PRIu16 << "\n" << QUICLY_ERROR_GET_ERROR_CODE(err) << std::endl;
    quicly_close(stream->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0), "");
}

void TrafGen::q_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{

    custom_quicly_streambuf_t *sbuf = (custom_quicly_streambuf_t *) stream->data;
    TrafGen *ctx = (TrafGen *) sbuf->user_ctx;
    /* read input to receive buffer */
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
        return ;

    if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
        /* obtain contiguous bytes from the receive buffer */
        ptls_iovec_t input = quicly_streambuf_ingress_get(stream);

        quicly_stream_id_t id = stream->stream_id;
        uint8_t rcode = input.base[3] & 0xf; //dns response code

        ctx->_metrics->receive(ctx->_open_streams[id].send_time, rcode, ctx->_open_streams.size());
        ctx->_open_streams.erase(id);


        /* remove used bytes from receive buffer */
        quicly_streambuf_ingress_shift(stream, input.len);
    }
}

int TrafGen::q_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    custom_quicly_stream_open_t *self_ptr = (custom_quicly_stream_open_t *) self;
    static const quicly_stream_callbacks_t stream_callbacks = {
        quicly_streambuf_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, q_on_stop_sending, q_on_receive,
        q_on_receive_reset};
    int ret;

    if ((ret = quicly_streambuf_create(stream, sizeof(custom_quicly_streambuf_t))) != 0)
        return ret;
    custom_quicly_streambuf_t *sbuf = (custom_quicly_streambuf_t *) stream->data;
    sbuf->user_ctx = self_ptr->user_ctx;

    stream->callbacks = &stream_callbacks;
    return 0;
}

static void q_on_closed_by_remote(quicly_closed_by_remote_t *self, quicly_conn_t *conn, int err, uint64_t frame_type,
                                const char *reason, size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        fprintf(stderr, "transport close:code=0x%" PRIx16 ";frame=%" PRIu64 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err),
                frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "application close:code=0x%" PRIx16 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len,
                reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        fprintf(stderr, "stateless reset\n");
    } else if (err == QUICLY_ERROR_NO_COMPATIBLE_VERSION) {
        fprintf(stderr, "no compatible version\n");
    } else {
        fprintf(stderr, "unexpected close:code=%d\n", err);
    }
}

void TrafGen::start_quic()
{

    // quic
    q_tlsctx = {
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
    };
    q_stream_open = {{q_on_stream_open}, this};
    q_closed_by_remote = {q_on_closed_by_remote};
    q_ctx = quicly_spec_context;
    q_ctx.tls = &q_tlsctx;
    quicly_amend_ptls_context(q_ctx.tls);
    q_ctx.stream_open = (quicly_stream_open_t *) &q_stream_open;
    q_ctx.closed_by_remote = &q_closed_by_remote;

    _udp_handle = _loop->resource<uvw::UDPHandle>(_traf_config->family);

    _udp_handle->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent &e, uvw::UDPHandle &) {
        if (0 == strcmp(e.name(), "EADDRNOTAVAIL"))
            throw std::runtime_error("unable to bind to ip address: " + _traf_config->bind_ip);
        _metrics->net_error();
    });

    if (_traf_config->family == AF_INET) {
        _udp_handle->bind<uvw::IPv4>(_traf_config->bind_ip, 0);
    } else {
        _udp_handle->bind<uvw::IPv6>(_traf_config->bind_ip, 0, uvw::UDPHandle::Bind::IPV6ONLY);
    }

    _metrics->trafgen_id(_udp_handle->sock().port);

    int ret;
    target_name = _traf_config->next_target().address;
    q_hand_prop = {0};
    q_hand_prop.client.negotiated_protocols.list = &alpn;
    q_hand_prop.client.negotiated_protocols.count = 1;

    target_addr.ss_family = _traf_config->family;
    inet_pton(target_addr.ss_family, target_name.data(), ((sockaddr*)&target_addr)->sa_data);

    _udp_handle->on<uvw::UDPDataEvent>([this](const uvw::UDPDataEvent &event, uvw::UDPHandle &h) {
        q_process_msg(q_conn, (const uint8_t*)event.data.get(), &event.sender, event.length);
    });

    _udp_handle->recv();

}
#endif

void TrafGen::start()
{

    if (_traf_config->protocol == Protocol::UDP) {
        start_udp();
        _sender_timer = _loop->resource<uvw::TimerHandle>();
        _sender_timer->on<uvw::TimerEvent>([this](const uvw::TimerEvent &event, uvw::TimerHandle &h) {
            udp_send();
        });
        _sender_timer->start(uvw::TimerHandle::Time{1}, uvw::TimerHandle::Time{_traf_config->s_delay});
    }
#ifdef QUIC_ENABLE
    else if (_traf_config->protocol == Protocol::QUIC) {
        start_quic();
            quic_send();
    }
#endif
    else {
        start_tcp_session();
    }

#ifdef QUIC_ENABLE
    if (_traf_config->protocol != Protocol::QUIC) {
#endif
        _timeout_timer = _loop->resource<uvw::TimerHandle>();
        _timeout_timer->on<uvw::TimerEvent>([this](const uvw::TimerEvent &event, uvw::TimerHandle &h) {
        handle_timeouts();
    });
        _timeout_timer->start(uvw::TimerHandle::Time{_traf_config->r_timeout * 1000}, uvw::TimerHandle::Time{1000});
#ifdef QUIC_ENABLE
    }
#endif

    _shutdown_timer = _loop->resource<uvw::TimerHandle>();
    if (_traf_config->protocol == Protocol::UDP) {
        _shutdown_timer->on<uvw::TimerEvent>([this](auto &, auto &) {
                if (_udp_handle.get()) {
                    _udp_handle->stop();
                }
                _timeout_timer->stop();
                if (_udp_handle.get()) {
                    _udp_handle->close();
                }
                if (_sender_timer.get()) {
                    _sender_timer->close();
                }
                _timeout_timer->close();
                _shutdown_timer->close();

                this->handle_timeouts();
                });
    }
#ifdef QUIC_ENABLE
    else if (_traf_config->protocol == Protocol::QUIC) {
        _shutdown_timer->on<uvw::TimerEvent>([this](auto &, auto &) {
                quicly_close(q_conn, 0, "");
                this->send_pending(q_conn); //gracefully stop & free the quic connection
                if (_udp_handle.get()) {
                    _udp_handle->stop();
                    _udp_handle->close();
                }
                if (_sender_timer.get()) {
                    _sender_timer->close();
                }
                _shutdown_timer->close();
                this->handle_timeouts();
                });
    }
#endif
    else {
        _shutdown_timer->on<uvw::TimerEvent>([this](auto &, auto &) {
            if (_tcp_handle.get()) {
                _tcp_handle->stop();
            }
            _timeout_timer->stop();
            if (_tcp_handle.get()) {
                _tcp_handle->close();
            }
            if (_sender_timer.get()) {
                _sender_timer->close();
            }
            _timeout_timer->close();
            _shutdown_timer->close();
            this->handle_timeouts();
            });
    }
}

/**
 * GC the in-flight list, handling timeouts.
 *
 * @param force_reset when true, time out all queries. this happens when e.g. a TCP connection is dropped.
 */
void TrafGen::handle_timeouts(bool force_reset)
{

    std::vector<uint16_t> timed_out;
    auto now = std::chrono::high_resolution_clock::now();
    for (auto i : _in_flight) {
        if (force_reset || std::chrono::duration_cast<std::chrono::seconds>(now - i.second.send_time).count() >= _traf_config->r_timeout) {
            timed_out.push_back(i.first);
        }
    }
    for (auto i : timed_out) {
        _in_flight.erase(i);
        _metrics->timeout(_in_flight.size());
        _free_id_list.push_back(i);
    }
}

void TrafGen::stop()
{
    _stopping = true;
    if (_sender_timer.get()) {
        _sender_timer->stop();
    }

#ifdef QUIC_ENABLE
    long shutdown_length = (_in_flight.size()||_open_streams.size())
        ? (_traf_config->r_timeout * 1000) : 1;
#else
    long shutdown_length = (_in_flight.size()) ? (_traf_config->r_timeout * 1000) : 1;
#endif
    _shutdown_timer->start(uvw::TimerHandle::Time{shutdown_length}, uvw::TimerHandle::Time{0});

}

#ifdef QUIC_ENABLE
void TrafGen::q_process_msg(quicly_conn_t *conn, const uint8_t *src, const uvw::Addr *src_addr, size_t dgram_len)
{
    size_t off = 0;
    assert(conn);

    /* split UDP datagram into multiple QUIC packets */
    while (off < dgram_len) {
        quicly_decoded_packet_t decoded;
        if (quicly_decode_packet(&q_ctx, &decoded, src, dgram_len, &off) == SIZE_MAX)
            break;
        /* TODO match incoming packets to connections, handle version negotiation, rebinding, retry, etc. */

        int ret;
        /* let the current connection handle ingress packets */
        sockaddr sa;
        if (_traf_config->family == AF_INET) {
            uv_ip4_addr(src_addr->ip.data(), src_addr->port, (sockaddr_in *) &sa);
        } else {
            uv_ip6_addr(src_addr->ip.data(), src_addr->port, (sockaddr_in6 *) &sa);
        }
        ret = quicly_receive(conn, nullptr, &sa, &decoded);

        this->send_pending(conn);
        if (ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED) {
            return;
        }

    }
}
#endif
