// Copyright 2017 NSONE, Inc

#include <ctime>
#include <iostream>
#include <sstream>

#include "metrics.h"
#include "version.h"

#include <ldns/util.h>

using json = nlohmann::json;

extern ldns_lookup_table ldns_rcodes[];

std::shared_ptr<Metrics> MetricsMgr::create_trafgen_metrics()
{
    auto m = std::make_shared<Metrics>(_loop);
    _metrics.push_back(m);
    return m;
}

void MetricsMgr::start()
{
    time_t now;
    time(&now);
    char buf[25] = {0};
    strftime(buf, sizeof buf, "%FT%TZ", gmtime(&now));
    _start_ts = buf;

    // XXX TODO make unique among different hosts
    std::size_t hash = std::hash<char *>{}(buf);
    std::stringstream sstr;
    sstr << std::hex << hash;
    _run_id = sstr.str();

    if (!_config->output_file().empty()) {
        _metric_file.open(_config->output_file(), std::ofstream::out | std::ofstream::app);
        if (!_metric_file.is_open()) {
            throw std::runtime_error("unable to open metric output file");
        }
        header_to_disk();
    }
    _metric_period_timer = _loop->resource<uvw::timer_handle>();
    _metric_period_timer->on<uvw::timer_event>([this](const auto &, auto &) {
        this->periodic_stats();
    });
    _metric_period_timer->start(uvw::timer_handle::time{1000}, uvw::timer_handle::time{1000});
    _start_time = std::chrono::high_resolution_clock::now();
    _qps_clock = std::chrono::high_resolution_clock::now();
}

void MetricsMgr::update_runtime()
{
    _stop_time = std::chrono::high_resolution_clock::now();
    _runtime_s = (_stop_time - _start_time).count() * Metrics::HR_TO_SEC_MULT;
}

void MetricsMgr::stop()
{
    periodic_stats();
    _metric_period_timer->stop();
    _metric_period_timer->close();
}

void MetricsMgr::header_to_disk()
{
    json j;

    j["version"] = FLAME_VERSION_NUM;
    j["cmdline"] = _cmdline;
    j["start_timestamp"] = _start_ts;
    j["run_id"] = _run_id;

    _metric_file << j << std::endl;
}

void MetricsMgr::flush_to_disk()
{
    update_runtime();
    json j;
    j["period_number"] = _aggregate_count;
    j["total_s_count"] = _agg_total_s_count;
    j["total_r_count"] = _agg_total_r_count;
    j["period_timeouts"] = _agg_period_timeouts;
    j["total_timeouts"] = _agg_total_timeouts;
    j["period_in_flight"] = _agg_period_in_flight;
    j["total_bad_count"] = _agg_total_bad_count;
    j["period_bad_count"] = _agg_period_bad_count;
    j["total_response_avg_ms"] = _agg_total_response_avg_ms;
    j["total_response_min_ms"] = _agg_total_response_min_ms;
    j["total_response_max_ms"] = _agg_total_response_max_ms;
    j["period_response_avg_ms"] = _agg_period_response_avg_ms;
    j["period_response_min_ms"] = _agg_period_response_min_ms;
    j["period_response_max_ms"] = _agg_period_response_max_ms;
    j["total_qps_r_avg"] = _agg_total_qps_r_avg;
    j["total_qps_s_avg"] = _agg_total_qps_s_avg;
    j["total_net_errors"] = _agg_total_net_errors;
    j["total_tcp_connections"] = _agg_total_tcp_connections;
    j["total_pkt_size_avg"] = _agg_total_pkt_size_avg;
    j["period_net_errors"] = _agg_period_net_errors;
    j["period_pkt_size_avg"] = _agg_period_pkt_size_avg;
    j["runtime_s"] = _runtime_s;
    j["run_id"] = _run_id;
    for (auto i : _response_codes) {
        j["total_responses"][ldns_lookup_by_id(ldns_rcodes, i.first)->name] = i.second;
    }
    _metric_file << j << std::endl;
}

void MetricsMgr::display_final_text()
{
    std::cout << std::endl;
    std::cout << "------" << std::endl;
    std::cout << "run id      : " << _run_id << std::endl;
    std::cout << "run start   : " << _start_ts << std::endl;
    std::cout << "runtime     : " << _runtime_s << " s" << std::endl;
    std::cout << "total sent  : " << _agg_total_s_count << std::endl;
    std::cout << "total rcvd  : " << _agg_total_r_count << std::endl;
    std::cout << "min resp    : " << _agg_total_response_min_ms << " ms" << std::endl;
    std::cout << "avg resp    : " << _agg_total_response_avg_ms << " ms" << std::endl;
    std::cout << "max resp    : " << _agg_total_response_max_ms << " ms" << std::endl;
    std::cout << "avg r qps   : " << _agg_total_qps_r_avg << std::endl;
    std::cout << "avg s qps   : " << _agg_total_qps_s_avg << std::endl;
    std::cout << "avg pkt     : " << _agg_total_pkt_size_avg << " bytes" << std::endl;
    std::cout << "tcp conn.   : " << _agg_total_tcp_connections << std::endl;
    std::cout << "timeouts    : " << _agg_total_timeouts << " ("
              << (((double)_agg_total_timeouts / _agg_total_s_count) * 100) << "%) " << std::endl;
    std::cout << "bad recv    : " << _agg_total_bad_count << std::endl;
    std::cout << "net errors  : " << _agg_total_net_errors << std::endl;
    if (_response_codes.size()) {
        std::cout << "responses   :" << std::endl;
        for (auto i : _response_codes) {
            std::cout << "  " << ldns_lookup_by_id(ldns_rcodes, i.first)->name << ": " << i.second << std::endl;
        }
    }
}

void MetricsMgr::aggregate(bool no_avgs)
{

    _aggregate_count++;

    for (const auto &i : _metrics) {
        aggregate_trafgen(i.get());
    }

    if (!no_avgs) {
        // average calculations
        auto now = std::chrono::high_resolution_clock::now();
        auto delta = std::chrono::duration_cast<std::chrono::nanoseconds>(now - _qps_clock).count();
        if (delta) {
            //            double delta_s = delta * Metrics::HR_TO_SEC_MULT;
            // note: currently tied to _metric_period_timer and _agg_period_X_count instead of _qps_clock.
            // revisit this if it becomes inaccurate.
            if (_agg_period_s_count) {
                _avg_qps_calc_s_count++;
                _agg_total_qps_s_avg = (_agg_period_s_count + (_agg_total_qps_s_avg * (_avg_qps_calc_s_count - 1))) / _avg_qps_calc_s_count;
            }
            if (_agg_period_r_count) {
                _avg_qps_calc_r_count++;
                _agg_total_qps_r_avg = (_agg_period_r_count + (_agg_total_qps_r_avg * (_avg_qps_calc_r_count - 1))) / _avg_qps_calc_r_count;
            }
        }

        // TODO avg of averages, here be dragons
        auto rcv_cnt = 0;
        for (const auto &i : _metrics) {
            if (i->_period_r_count) {
                rcv_cnt++;
                _agg_period_response_avg_ms += i->_period_response_avg_ms;
            }
            _agg_period_pkt_size_avg += i->_period_pkt_size_avg;
        }
        _agg_period_response_avg_ms /= rcv_cnt;
        _agg_period_pkt_size_avg /= _metrics.size();
        if (_agg_period_response_avg_ms) {
            _agg_total_response_avg_ms = (_agg_period_response_avg_ms + (_agg_total_response_avg_ms * (_aggregate_count - 1))) / _aggregate_count;
        }
        if (_agg_period_pkt_size_avg) {
            _agg_total_pkt_size_avg = (_agg_period_pkt_size_avg + (_agg_total_pkt_size_avg * (_aggregate_count - 1))) / _aggregate_count;
        }
    }

    for (const auto &i : _metrics) {
        i->reset_periodic_stats();
    }

    _qps_clock = std::chrono::high_resolution_clock::now();
}

void MetricsMgr::periodic_stats()
{

    // COLLECT/AGGREGATE
    aggregate();

    // DISPLAY
    if (_config->verbosity()) {
        display_periodic_stats();
    }

    // FLUSH
    if (_metric_file.is_open()) {
        flush_to_disk();
    }

    // RESET
    // ints
    _agg_period_r_count = _agg_period_s_count = _agg_period_in_flight = _agg_period_timeouts = _agg_period_bad_count = _agg_period_net_errors = _agg_period_tcp_connections = 0;
    // doubles
    _agg_period_response_avg_ms = _agg_period_response_max_ms = _agg_period_response_min_ms = _agg_period_pkt_size_avg = 0.0;
}

void MetricsMgr::display_periodic_stats()
{
    update_runtime();
    std::cout << _runtime_s << "s: "
              << "send: " << _agg_period_s_count << ", avg send: " << _agg_total_qps_s_avg << ", recv: "
              << _agg_period_r_count << ", avg recv: " << _agg_total_qps_r_avg << ", min/avg/max resp: "
              << _agg_period_response_min_ms << "/" << _agg_period_response_avg_ms << "/" << _agg_period_response_max_ms
              << "ms"
              << ", in flight: " << _agg_period_in_flight
              << ", timeouts: " << _agg_period_timeouts << std::endl;
}

void MetricsMgr::finalize()
{
    // we avoid calculating averages after main trafgen period
    aggregate(true);
    if (_config->verbosity()) {
        if (_agg_period_r_count) {
            display_periodic_stats();
        }
        display_final_text();
    }
    if (_metric_file.is_open()) {
        flush_to_disk();
        _metric_file.close();
    }
}

void MetricsMgr::aggregate_trafgen(const Metrics *m)
{

    update_runtime();

    if (_per_trafgen_metrics && _metric_file.is_open()) {
        // record per trafgen metrics to out file
        json j;
        j["period_number"] = _aggregate_count;
        j["run_id"] = _run_id;
        j["runtime_s"] = _runtime_s;
        m->toJSON(j);
        _metric_file << j.dump() << std::endl;
    }

    // aggregate this trafgen
    _agg_total_r_count += m->_period_r_count;
    _agg_total_s_count += m->_period_s_count;

    _agg_period_s_count += m->_period_s_count;
    _agg_period_r_count += m->_period_r_count;

    _agg_period_in_flight += m->_in_flight;

    _agg_period_timeouts += m->_period_timeouts;
    _agg_total_timeouts += m->_period_timeouts;

    _agg_period_bad_count += m->_period_bad_count;
    _agg_total_bad_count += m->_period_bad_count;

    _agg_period_net_errors += m->_period_net_errors;
    _agg_total_net_errors += m->_period_net_errors;

    _agg_period_tcp_connections += m->_period_tcp_connections;
    _agg_total_tcp_connections += m->_period_tcp_connections;

    if (_agg_total_response_min_ms == 0) {
        _agg_total_response_min_ms = m->_period_response_min_ms;
    } else if (m->_period_response_min_ms && m->_period_response_min_ms < _agg_total_response_min_ms) {
        _agg_total_response_min_ms = m->_period_response_min_ms;
    }

    if (_agg_period_response_min_ms == 0) {
        _agg_period_response_min_ms = m->_period_response_min_ms;
    } else if (m->_period_response_min_ms && m->_period_response_min_ms < _agg_period_response_min_ms) {
        _agg_period_response_min_ms = m->_period_response_min_ms;
    }

    if (_agg_total_response_max_ms == 0) {
        _agg_total_response_max_ms = m->_period_response_max_ms;
    } else if (m->_period_response_max_ms && m->_period_response_max_ms > _agg_total_response_max_ms) {
        _agg_total_response_max_ms = m->_period_response_max_ms;
    }

    if (_agg_period_response_max_ms == 0) {
        _agg_period_response_max_ms = m->_period_response_max_ms;
    } else if (m->_period_response_max_ms && m->_period_response_max_ms > _agg_period_response_max_ms) {
        _agg_period_response_max_ms = m->_period_response_max_ms;
    }

    for (auto i : m->_response_codes) {
        _response_codes[i.first] += i.second;
    }
}
std::string MetricsMgr::toJSON() const
{
    json j;
    j["period_number"] = _aggregate_count;
    j["run_id"] = _run_id;
    j["runtime_s"] = _runtime_s;
    int n = 0;
    for (const auto &i : _metrics) {
        i->toJSON(j["trafgen"][n++]);
    }
    return j.dump();
}

// ----------------------

void Metrics::timeout(u_long in_f)
{
    _period_timeouts++;
    _in_flight = in_f;
}

void Metrics::net_error()
{
    _period_net_errors++;
}

void Metrics::send(u_long size, u_long i, u_long in_f)
{
    _in_flight = in_f;
    _total_s_count += i;
    _period_s_count += i;
    _period_pkt_size_avg = (size + (_period_pkt_size_avg * (_period_s_count - i))) / _period_s_count;
}

void Metrics::bad_receive(u_long in_f)
{
    _in_flight = in_f;
    _period_bad_count++;
    _total_r_count++;
    _period_r_count++;
}

void Metrics::receive(const std::chrono::high_resolution_clock::time_point &rcv_time, uint8_t rcode, u_long in_f)
{
    auto now = std::chrono::high_resolution_clock::now();
    auto q_latency = now - rcv_time;
    double q_latency_ms = q_latency.count() * Metrics::HR_TO_MSEC_MULT;
    _in_flight = in_f;
    _response_codes[rcode]++;
    _total_r_count++;
    _period_r_count++;
    _period_response_avg_ms = (q_latency_ms + (_period_response_avg_ms * (_period_r_count - 1))) / _period_r_count;
    if (q_latency_ms > _period_response_max_ms) {
        _period_response_max_ms = q_latency_ms;
    }
    if (_period_response_min_ms == 0 || q_latency_ms < _period_response_min_ms) {
        _period_response_min_ms = q_latency_ms;
    }
}

void Metrics::reset_periodic_stats()
{
    // reset counters for period
    _period_r_count = _period_s_count = _period_bad_count = _period_net_errors = _period_timeouts = _period_tcp_connections = 0;
    _period_response_avg_ms = _period_response_max_ms = _period_response_min_ms = _period_pkt_size_avg = 0.0;
    _response_codes.clear();
}

void Metrics::trafgen_id(u_int port)
{
    //    std::size_t hash = std::hash<unsigned int>{}(port);
    std::stringstream sstr;
    //    sstr << std::hex << hash;
    sstr << port;
    _trafgen_id = sstr.str();
}

void Metrics::toJSON(nlohmann::json &j) const
{
    j["period_s_count"] = _period_s_count;
    j["period_r_count"] = _period_r_count;

    j["trafgen_id"] = _trafgen_id;

    j["period_timeouts"] = _period_timeouts;
    j["in_flight"] = _in_flight;
    j["period_bad_count"] = _period_bad_count;
    j["period_response_avg_ms"] = _period_response_avg_ms;
    j["period_response_min_ms"] = _period_response_min_ms;
    j["period_response_max_ms"] = _period_response_max_ms;
    j["period_net_errors"] = _period_net_errors;
    j["period_tcp_connections"] = _period_tcp_connections;
    j["pkt_size_avg"] = _period_pkt_size_avg;
    for (auto i : _response_codes) {
        j["responses"][ldns_lookup_by_id(ldns_rcodes, i.first)->name] = i.second;
    }
}
