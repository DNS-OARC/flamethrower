// Copyright 2017 NSONE, Inc

#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "config.h"
#include "http.h"
#include "httpssession.h"
#include "metrics.h"
#include "query.h"
#include "target.h"
#include "tcpsession.h"
#include "tokenbucket.h"

#include <uvw.hpp>

enum class Protocol {
    UDP,
    HTTPS,
    TCP,
    DOT,
};

struct TrafGenConfig {
    std::vector<Target> target_list;
    unsigned int _current_target{0};
    int family{0};
    std::string bind_ip;
    unsigned int port{53};
    int r_timeout{3};
    long s_delay{1};
    long batch_count{10};
    Protocol protocol{Protocol::UDP};
    HTTPMethod method{HTTPMethod::POST};
    const Target& next_target()
    {
        const Target& next = target_list[_current_target];
        _current_target++;
        if (_current_target >= target_list.size())
            _current_target = 0;
        return next;
    }
};

class TrafGen
{

    std::shared_ptr<uvw::Loop> _loop;
    std::shared_ptr<Metrics> _metrics;
    std::shared_ptr<Config> _config;
    std::shared_ptr<TrafGenConfig> _traf_config;
    std::shared_ptr<QueryGenerator> _qgen;
    std::shared_ptr<TokenBucket> _rate_limit;

    std::shared_ptr<uvw::UDPHandle> _udp_handle;
    std::shared_ptr<uvw::TcpHandle> _tcp_handle;
    std::shared_ptr<TCPSession> _tcp_session;

    std::shared_ptr<uvw::TimerHandle> _sender_timer;
    std::shared_ptr<uvw::TimerHandle> _timeout_timer;
    std::shared_ptr<uvw::TimerHandle> _shutdown_timer;
    std::shared_ptr<uvw::TimerHandle> _finish_session_timer;

    // a hash of in flight queries, keyed by query id
    std::unordered_map<uint16_t, Query> _in_flight;
    // a randomized list of query ids that are not currently in flight
    std::vector<uint16_t> _free_id_list;

    bool _stopping;

    void handle_timeouts(bool force_reset = false);

    void process_wire(const char data[], size_t len);

    void start_udp();
    void udp_send();

    void start_tcp_session();
    void start_wait_timer_for_tcp_finish();

public:
    TrafGen(std::shared_ptr<uvw::Loop> l,
        std::shared_ptr<Metrics> s,
        std::shared_ptr<Config> c,
        std::shared_ptr<TrafGenConfig> tgc,
        std::shared_ptr<QueryGenerator> q,
        std::shared_ptr<TokenBucket> r);

    void start();

    void stop();
    std::vector<uint16_t>::size_type in_flight_cnt()
    {
        return _in_flight.size();
    }
};
