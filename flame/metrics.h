// Copyright 2017 NSONE, Inc

#pragma once

#include "config.h"

#include <chrono>
#include <fstream>
#include <memory>
#include <unordered_map>

#include <uvw.hpp>

class Metrics;

class MetricsMgr
{
    std::chrono::high_resolution_clock::time_point _start_time;
    std::chrono::high_resolution_clock::time_point _stop_time;

    std::shared_ptr<Config> _config;
    std::shared_ptr<uvw::Loop> _loop;

    // aggregation and output
    std::shared_ptr<uvw::TimerHandle> _metric_period_timer;

    // metric output file, if enabled
    std::ofstream _metric_file;

    // metric counters, one per TrafGen
    std::vector<std::shared_ptr<Metrics>> _metrics;

    std::unordered_map<uint8_t, u_long> _response_codes;

    // command line XXX move to config
    std::string _cmdline;

    // unique run id
    std::string _run_id;
    std::string _start_ts;
    double _runtime_s{0.0};

    // qps avg calculations
    u_long _avg_qps_calc_r_count{0};
    u_long _avg_qps_calc_s_count{0};
    std::chrono::high_resolution_clock::time_point _qps_clock;

    // times we've aggregated (used in avg calcs)
    u_long _aggregate_count{0};

    // aggregated totals throughout entire run
    u_long _agg_total_r_count{0};
    u_long _agg_total_s_count{0};
    u_long _agg_total_qps_r_avg{0};
    u_long _agg_total_qps_s_avg{0};
    u_long _agg_total_timeouts{0};
    u_long _agg_total_bad_count{0};
    u_long _agg_total_net_errors{0};
    u_long _agg_total_tcp_connections{0};
    double _agg_total_response_min_ms{0.0};
    double _agg_total_response_max_ms{0.0};

    // TODO current avg of avgs, switch to percentiles
    double _agg_total_pkt_size_avg{0.0};
    double _agg_total_response_avg_ms{0.0};

    // aggregated totals for single time period
    // these all need to be reset in reset_periodic_stats()
    u_long _agg_period_r_count{0};
    u_long _agg_period_s_count{0};
    u_long _agg_period_in_flight{0};
    u_long _agg_period_timeouts{0};
    u_long _agg_period_bad_count{0};
    u_long _agg_period_net_errors{0};
    u_long _agg_period_tcp_connections{0};
    double _agg_period_response_min_ms{0.0};
    double _agg_period_response_max_ms{0.0};

    // TODO avg of avgs, switch to percentiles
    double _agg_period_pkt_size_avg{0.0};
    double _agg_period_response_avg_ms{0.0};

    // do we record each individual trafgen, or only aggregate?
    bool _per_trafgen_metrics{true};

    void header_to_disk();
    void flush_to_disk();
    void periodic_stats();

    // console display
    void display_periodic_stats();
    void display_final_text();

    void update_runtime();

    void aggregate(bool no_avgs = false);
    void aggregate_trafgen(const Metrics *m);

public:
    MetricsMgr(std::shared_ptr<uvw::Loop> l, std::shared_ptr<Config> c, const std::string &cmdline)
        : _loop(l)
        , _config(c)
        , _cmdline(cmdline)
    {
    }

    void start();

    void stop();

    void finalize();

    std::shared_ptr<Metrics> create_trafgen_metrics();
};

class Metrics
{
    friend class MetricsMgr;

    std::shared_ptr<uvw::Loop> _loop;
    MetricsMgr &_mgr;

    std::string _trafgen_id;

    // total sends entire lifetime
    u_long _total_r_count{0};
    u_long _total_s_count{0};

    // period counters, reset each flush to MetricsMgr
    u_long _period_r_count{0};
    u_long _period_s_count{0};
    u_long _period_bad_count{0};
    u_long _period_net_errors{0};
    u_long _period_timeouts{0};
    u_long _period_tcp_connections{0};
    double _period_response_avg_ms{0.0};
    double _period_response_min_ms{0.0};
    double _period_response_max_ms{0.0};
    double _period_pkt_size_avg{0.0};

    // updated during operations that adjust in_flight like send, recv, timeout
    u_long _in_flight{0};

    std::unordered_map<uint8_t, u_long> _response_codes;

public:
    constexpr static const double HR_TO_SEC_MULT = 0.000000001;
    constexpr static const double HR_TO_MSEC_MULT = 0.000001;

    Metrics(std::shared_ptr<uvw::Loop> l, MetricsMgr &m)
        : _loop(l)
        , _mgr(m)
    {
    }

    void trafgen_id(u_int port);

    void receive(const std::chrono::high_resolution_clock::time_point &rcv_time, uint8_t rcode, u_long in_f);

    void reset_periodic_stats();

    void timeout(u_long in_f);

    void net_error();

    void send(u_long size, u_long i, u_long in_f);

    void tcp_connection()
    {
        _period_tcp_connections++;
    }

    void bad_receive(u_long in_f);
};
