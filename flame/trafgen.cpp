// Copyright 2017-2019 NSONE, Inc

#include <algorithm>
#include <iostream>
#include <memory>
#include <random>
#include <string>

#include "trafgen.h"
#include "tcptlssession.h"

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

#ifdef DOQ_ENABLE
    _q_next_cid = new_connection_id();
    if (_traf_config->protocol == Protocol::DOQ) {
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
        if(_traf_config->protocol != Protocol::DOH)
#endif
        {
            auto qt = _qgen->next_tcp(id_list);

            // async send the batch. fires WriteEvent when finished sending.
            _tcp_session->write(std::move(std::get<0>(qt)), std::get<1>(qt));

            _metrics->send(std::get<1>(qt), id_list.size(), _in_flight.size());
        }
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

        if (this->in_flight() && (cur_wait_ms < (_traf_config->r_timeout * 1000))) {
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

#ifdef DOQ_ENABLE
        if (_traf_config->protocol == Protocol::DOQ) {
            _quic_session->close();
            _quic_session.reset();
            handle_timeouts(true);
            _finish_session_timer.reset();
            if (!_stopping)
                start_quic_session();
        } else
#endif
        {
            _tcp_handle->close();
        }
    });
    _finish_session_timer->start(uvw::TimerHandle::Time{1}, uvw::TimerHandle::Time{50});
}

#ifdef DOQ_ENABLE

void TrafGen::start_quic_session()
{

    assert(_udp_handle.get());
    assert(_quic_session.get() == 0);
    if (_qgen->finished())
        return;
    _finish_session_timer.reset();

    Target current_target = _traf_config->next_target();

    // By the rfc, all send queries are considered to be a SERVFAIL on connection failure (section 5.4).
    auto conn_error = [this]() {
        _metrics->net_error();
        for (auto i : _open_streams) {
            _metrics->receive(_open_streams[i.first].send_time, 2, _open_streams.size());
        }
    };
    // The pending requests are simly cleared because they are not yet sent if
    // this event occurs
    auto conn_refused = [this]() {
        _open_streams.clear();
        _metrics->net_error();
    };
    auto stream_rst = [this](stream_id_t id) {
        _metrics->receive(_open_streams[id].send_time, 2, _open_streams.size());
        _open_streams.erase(id);
    };
    auto got_dns_msg = [this](std::vector<char> data, stream_id_t id) {
        if (data.size() <= 12) {
            _metrics->bad_receive(_in_flight.size());
            return;
        }
        uint8_t rcode = data[3] & 0xf; //dns response code
        _metrics->receive(_open_streams[id].send_time, rcode, _open_streams.size());
        _open_streams.erase(id);
    };

    _quic_session = std::make_shared<QUICSession>(_udp_handle, got_dns_msg, conn_refused, conn_error, stream_rst,
            current_target, _traf_config->port, _traf_config->family, _q_next_cid);
    _q_next_cid = next_connection_id(_q_next_cid);

    for (int i = 0; i < _traf_config->batch_count; i++) {
        if (_open_streams.size() == std::numeric_limits<uint16_t>::max()) {
            std::cerr << "max in flight reached" << std::endl;
            return;
        }
        if (_rate_limit && !_rate_limit->consume(1, this->_loop->now()))
            break;
        //in doq, dns messages ID are set to 0
        auto qt = _qgen->next_udp(0);

        stream_id_t id = _quic_session->write(std::move(std::get<0>(qt)), std::get<1>(qt));

        _metrics->send(std::get<1>(qt), 1, _open_streams.size());
        _open_streams[id].send_time = std::chrono::high_resolution_clock::now();
    }

    _quic_session->send_pending();
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

#ifdef DOQ_ENABLE

void TrafGen::start_quic()
{

    _udp_handle = _loop->resource<uvw::UDPHandle>(_traf_config->family);

    _udp_handle->on<uvw::ErrorEvent>([this](const uvw::ErrorEvent &e, uvw::UDPHandle &) {
        if (0 == strcmp(e.name(), "EADDRNOTAVAIL"))
            throw std::runtime_error("unable to bind to ip address: " + _traf_config->bind_ip);
        _metrics->net_error();
    });

    if (_traf_config->family == AF_INET) {
        _udp_handle->bind<uvw::UDPHandle::IPv4>(_traf_config->bind_ip, 0);
    } else {
        _udp_handle->bind<uvw::UDPHandle::IPv6>(_traf_config->bind_ip, 0);
    }

    _metrics->trafgen_id(_udp_handle->sock().port);

    _udp_handle->on<uvw::UDPDataEvent>([this](const uvw::UDPDataEvent &event, uvw::UDPHandle &h) {
        if (_quic_session)
            _quic_session->receive_data(event.data.get(), event.length, &event.sender);
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
#ifdef DOQ_ENABLE
    else if (_traf_config->protocol == Protocol::DOQ) {
        start_quic();
        start_quic_session();
    }
#endif
    else {
        start_tcp_session();
    }

        _timeout_timer = _loop->resource<uvw::TimerHandle>();
        _timeout_timer->on<uvw::TimerEvent>([this](const uvw::TimerEvent &event, uvw::TimerHandle &h) {
        handle_timeouts();
    });
        _timeout_timer->start(uvw::TimerHandle::Time{_traf_config->r_timeout * 1000}, uvw::TimerHandle::Time{1000});

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
#ifdef DOQ_ENABLE
    else if (_traf_config->protocol == Protocol::DOQ) {
        _shutdown_timer->on<uvw::TimerEvent>([this](auto &, auto &) {
                if (_udp_handle.get())
                    _udp_handle->stop();
                if (_quic_session.get())
                    _quic_session->close();

                _timeout_timer->stop();
                if (_udp_handle.get())
                    _udp_handle->close();
                _timeout_timer->close();
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

    auto now = std::chrono::high_resolution_clock::now();
#ifdef DOQ_ENABLE
    if (_traf_config->protocol == Protocol::DOQ) {
        std::vector<stream_id_t> timed_out;
        for (auto i : _open_streams) {
            if (force_reset || std::chrono::duration_cast<std::chrono::seconds>(now - i.second.send_time).count() >= _traf_config->r_timeout) {
                timed_out.push_back(i.first);
            }
        }
        for (auto i : timed_out) {
            _open_streams.erase(i);
            _metrics->timeout(_open_streams.size());
        }
    } else
#endif
    {
        std::vector<uint16_t> timed_out;
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
}

bool TrafGen::in_flight()
{
#ifdef DOQ_ENABLE
    return _in_flight.size()||_open_streams.size();
#else
    return _in_flight.size();
#endif
}

void TrafGen::stop()
{
    _stopping = true;
    if (_sender_timer.get()) {
        _sender_timer->stop();
    }

    long shutdown_length = this->in_flight() ? (_traf_config->r_timeout * 1000) : 1;
    _shutdown_timer->start(uvw::TimerHandle::Time{shutdown_length}, uvw::TimerHandle::Time{0});

}
