// Copyright 2017 NSONE, Inc

#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "config.h"
#include "metrics.h"
#include "query.h"
#include "tcpsession.h"

#include "quicly.h"
#include "quicly/streambuf.h"

#include <TokenBucket.h>
#include <uvw.hpp>

enum class Protocol {
    UDP,
    TCP,
    TCPTLS,
    QUIC,
};

struct TrafGenConfig {
    std::string target_address;
    int family{0};
    unsigned int port{53};
    int r_timeout{3};
    long s_delay{1};
    long batch_count{10};
    Protocol protocol{Protocol::UDP};
    struct sockaddr_storage sa;
    socklen_t salen;
    quicly_context_t q_ctx;
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

    quicly_conn_t *q_conn;

    std::shared_ptr<uvw::TimerHandle> _sender_timer;
    std::shared_ptr<uvw::TimerHandle> _timeout_timer;
    std::shared_ptr<uvw::TimerHandle> _shutdown_timer;
    std::shared_ptr<uvw::TimerHandle> _finish_session_timer;

    // a hash of in flight queries, keyed by query id
    std::unordered_map<uint16_t, Query> _in_flight;
    // a randomized list of query ids that are not currently in flight
    std::vector<uint16_t> _free_id_list;

    quicly_cid_plaintext_t q_next_cid;

    bool _stopping;

    void handle_timeouts(bool force_reset = false);

    void process_wire(const char data[], size_t len);

    void start_udp();
    void start_quic();
    void udp_send();

    void start_tcp_session();
    void start_wait_timer_for_tcp_finish();

    int q_run_client(int fd, const char *host, struct sockaddr *sa, socklen_t salen);
    int q_run_loop(int fd, quicly_conn_t *conn, int (*stdin_read_cb)(quicly_conn_t *conn));
    int q_send_one(int fd, quicly_datagram_t *p);
    void q_process_msg(quicly_conn_t *conn, const uint8_t *src, size_t dgram_len);
    int q_read_stdin(quicly_conn_t *conn);

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
