// Copyright 2017 NSONE, Inc

#include <algorithm>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <random>
#include <string>

#include "tcptlssession.h"
#include "trafgen.h"

TrafGen::TrafGen(std::shared_ptr<uvw::loop> l,
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
    , _started_sending(false)
    , _stopping(false)
{
    // build a list of random ids we will use for queries
    for (uint16_t i = 0; i < std::numeric_limits<uint16_t>::max(); i++)
        _free_id_list.push_back(i);
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(_free_id_list.begin(), _free_id_list.end(), g);
    // allocate enough space for the amount of queries we expect to have in flight
    // max here is based on uint16, the number of ids
    _in_flight.reserve(std::numeric_limits<uint16_t>::max());
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

    _udp_handle = _loop->resource<uvw::udp_handle>(_traf_config->family);

    _udp_handle->on<uvw::error_event>([this](const uvw::error_event &e, uvw::udp_handle &) {
        if (0 == strcmp(e.name(), "EADDRNOTAVAIL"))
            throw std::runtime_error("unable to bind to ip address: " + _traf_config->bind_ip);
        _metrics->net_error();
    });

    if (_traf_config->family == AF_INET) {
        _udp_handle->bind(_traf_config->bind_ip, 0);
    } else {
        _udp_handle->bind(_traf_config->bind_ip, 0, uvw::udp_handle::udp_flags::IPV6ONLY);
    }

    _metrics->trafgen_id(_udp_handle->sock().port);

    _udp_handle->on<uvw::udp_data_event>([this](const uvw::udp_data_event &event, uvw::udp_handle &h) {
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
    _tcp_handle = _loop->resource<uvw::tcp_handle>(_traf_config->family);

    connect_tcp_events();

    if (_traf_config->family == AF_INET) {
        _tcp_handle->bind(_traf_config->bind_ip, 0);
    } else {
        _tcp_handle->bind(_traf_config->bind_ip, 0, uvw::tcp_handle::tcp_flags::IPV6ONLY);
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
            _started_sending = true;

#ifdef DOH_ENABLE
            // Send one by one with DoH
            if (_traf_config->protocol == Protocol::DOH) {
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
        if (_traf_config->protocol != Protocol::DOH) {
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
    if (_traf_config->protocol == Protocol::TCP) {
        _tcp_session = std::make_shared<TCPSession>(_tcp_handle, malformed_data, got_dns_message, connection_ready);
    } else if (_traf_config->protocol == Protocol::DOT) {
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

    // fires ConnectEvent when connected
    _tcp_handle->connect(reinterpret_cast<const sockaddr &>(current_target.address));
}

void TrafGen::connect_tcp_events()
{
    /** SOCKET CALLBACKS **/

    // SOCKET: local socket was closed, cleanup resources and possibly restart another connection
    _tcp_handle->on<uvw::close_event>([this](uvw::close_event &event, uvw::tcp_handle &h) {
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
    _tcp_handle->on<uvw::error_event>([this](uvw::error_event &event, uvw::tcp_handle &h) {
        if (_config->verbosity() > 1) {
            std::cerr << _tcp_handle->sock().ip << ":" << _tcp_handle->sock().port << " - " << event.what() << std::endl;
        }
        _metrics->net_error();
        // triggers an immediate connection retry.
        _tcp_handle->close();
    });

    // INCOMING: remote peer closed connection, EOF
    _tcp_handle->on<uvw::end_event>([this](uvw::end_event &event, uvw::tcp_handle &h) {
        _tcp_session->on_end_event();
    });

    // OUTGOING: we've finished writing all our data and are shutting down
    _tcp_handle->on<uvw::shutdown_event>([this](uvw::shutdown_event &event, uvw::tcp_handle &h) {
        _tcp_session->on_shutdown_event();
    });

    // INCOMING: remote peer sends data, pass to session
    _tcp_handle->on<uvw::data_event>([this](uvw::data_event &event, uvw::tcp_handle &h) {
        _tcp_session->receive_data(event.data.get(), event.length);
    });

    // OUTGOING: write operation has finished
    _tcp_handle->on<uvw::write_event>([this](uvw::write_event &event, uvw::tcp_handle &h) {
        if (!_finish_session_timer)
            start_wait_timer_for_tcp_finish();
    });

    // SOCKET: on connect
    _tcp_handle->on<uvw::connect_event>([this](uvw::connect_event &event, uvw::tcp_handle &h) {
        _tcp_session->on_connect_event();
        _metrics->tcp_connection();

        // start reading from incoming stream, fires DataEvent when receiving
        _tcp_handle->read();
    });
}

void TrafGen::start_wait_timer_for_tcp_finish()
{

    // wait for all responses, but no longer than query timeout
    // once we have all responses, or timed out, delay for delay time, then start over
    auto wait_time_start = std::chrono::high_resolution_clock::now();
    assert(_finish_session_timer.get() == 0);
    _finish_session_timer = _loop->resource<uvw::timer_handle>();
    _finish_session_timer->on<uvw::timer_event>([this, wait_time_start](const uvw::timer_event &event,
                                                    uvw::timer_handle &h) {
        auto now = std::chrono::high_resolution_clock::now();
        auto cur_wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - wait_time_start).count();

        if ((!_started_sending || _in_flight.size()) && (cur_wait_ms < (_traf_config->r_timeout * 1000))) {
            // queries in flight and timeout time not elapsed, still wait
            return;
        } else if (cur_wait_ms < (_traf_config->s_delay)) {
            // either timed out or nothing in flight. ensure delay period has passed
            // before restarting
            return;
        }

        // shut down timer and connection. TCP CloseEvent will handle restarting sends.
        _finish_session_timer->stop();
        _started_sending = false;
        _tcp_handle->stop();
        _finish_session_timer->close();
        _tcp_handle->close();
    });
    _finish_session_timer->start(uvw::timer_handle::time{1}, uvw::timer_handle::time{50});
}

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
        _udp_handle->send(reinterpret_cast<const sockaddr &>(_traf_config->next_target().address),
            std::move(std::get<0>(qt)),
            std::get<1>(qt));
        _metrics->send(std::get<1>(qt), 1, _in_flight.size());
        _in_flight[id].send_time = std::chrono::high_resolution_clock::now();
    }
}

void TrafGen::start()
{

    if (_traf_config->protocol == Protocol::UDP) {
        start_udp();
        _sender_timer = _loop->resource<uvw::timer_handle>();
        _sender_timer->on<uvw::timer_event>([this](const uvw::timer_event &event, uvw::timer_handle &h) {
            switch (_traf_config->protocol) {
            case Protocol::UDP:
                udp_send();
                break;
            case Protocol::TCP:
#ifdef DOH_ENABLE
            case Protocol::DOH:
#endif
            case Protocol::DOT:
                start_tcp_session();
                break;
            }
        });
        _sender_timer->start(uvw::timer_handle::time{1}, uvw::timer_handle::time{_traf_config->s_delay});
    } else {
        start_tcp_session();
    }

    _timeout_timer = _loop->resource<uvw::timer_handle>();
    _timeout_timer->on<uvw::timer_event>([this](const uvw::timer_event &event, uvw::timer_handle &h) {
        handle_timeouts();
    });
    _timeout_timer->start(uvw::timer_handle::time{_traf_config->r_timeout * 1000}, uvw::timer_handle::time{1000});

    _shutdown_timer = _loop->resource<uvw::timer_handle>();
    _shutdown_timer->on<uvw::timer_event>([this](auto &, auto &) {
        if (_udp_handle.get()) {
            _udp_handle->stop();
        }
        if (_tcp_handle.get()) {
            _tcp_handle->stop();
        }

        _timeout_timer->stop();

        if (_udp_handle.get()) {
            _udp_handle->close();
        }
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
    long shutdown_length = (_in_flight.size()) ? (_traf_config->r_timeout * 1000) : 1;
    _shutdown_timer->start(uvw::timer_handle::time{shutdown_length}, uvw::timer_handle::time{0});
}
