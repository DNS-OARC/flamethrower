// Copyright 2017 NSONE, Inc

#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "config.h"

#ifdef DOH_ENABLE
#include "http.h"
#include "httpssession.h"
#endif

#include "metrics.h"
#include "query.h"
#include "target.h"
#include "tcpsession.h"
#include "tokenbucket.h"

#ifdef QUIC_ENABLE
#include "quicly.h"
#include "quicly/streambuf.h"
#include "quicly/constants.h"
#endif

#include <uvw.hpp>

enum class Protocol {
    UDP,
    TCP,
#ifdef QUIC_ENABLE
    QUIC,
#endif
#ifdef DOH_ENABLE
    DOH,
#endif
    DOT,
};

#ifdef QUIC_ENABLE
/* needed to pass context to callback functions */
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
#endif

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
#ifdef DOH_ENABLE
    HTTPMethod method{HTTPMethod::POST};
#endif
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

#ifdef QUIC_ENABLE
    std::unordered_map<quicly_stream_id_t, Query> _open_streams;
#endif

    bool _stopping;

#ifdef QUIC_ENABLE
    struct sockaddr_storage target_addr;
    std::string target_name;
    //tells the negotiated protocol
    ptls_iovec_t alpn = ptls_iovec_init("doq", 3);
    quicly_conn_t *q_conn = NULL;
    //stores the cid for the next connection
    quicly_cid_plaintext_t q_next_cid = {0, 0, 0, 0};
    ptls_handshake_properties_t q_hand_prop;
    custom_quicly_stream_open_t q_stream_open;
    custom_quicly_closed_by_remote_t q_closed_by_remote;
    quicly_context_t q_ctx;
    ptls_context_t q_tlsctx;
#endif

    void handle_timeouts(bool force_reset = false);

    void process_wire(const char data[], size_t len);

    void start_udp();
    void udp_send();

    void start_tcp_session();
    void start_wait_timer_for_session_finish();

    bool in_flight();

#ifdef QUIC_ENABLE
    int send_pending(quicly_conn_t *conn);
    void start_quic();
    void quic_send();
    void q_process_msg(quicly_conn_t *conn, const uint8_t *src, const uvw::Addr *src_addr, size_t dgram_len);
    static void q_on_receive_reset(quicly_stream_t *stream, int err);
    static void q_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
    static int q_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
    static void q_on_closed_by_remote(quicly_closed_by_remote_t *self, quicly_conn_t *conn, int err, uint64_t frame_type, const char *reason, size_t reason_len);
#endif

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
