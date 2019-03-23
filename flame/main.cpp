// Copyright 2017 NSONE, Inc

#include <iostream>
#include <iterator>
#include <map>
#include <queue>
#include <sstream>
#include <string>
#include <vector>

#include "config.h"
#include "docopt.h"
#include "metrics.h"
#include "query.h"
#include "trafgen.h"
#include "utils.h"

#include <uvw.hpp>

#include "version.h"

#include "quicly.h"
#include "quicly/streambuf.h"

static const char USAGE[] =
    R"(Flamethrower.
    Usage:
      flame [-q QCOUNT] [-c TCOUNT] [-p PORT] [-d DELAY_MS] [-r RECORD] [-T QTYPE] [-o FILE]
            [-l LIMIT_SECS] [-t TIMEOUT] [-F FAMILY] [-f FILE] [-n LOOP] [-P PROTOCOL]
            [-Q QPS] [-g GENERATOR] [-v VERBOSITY] [-R] [--class CLASS] [--qps-flow SPEC]
            [--dnssec]
            TARGET [GENOPTS]...
      flame (-h | --help)
      flame --version

    Options:
      -h --help        Show this screen.
      --version        Show version.
      --class CLASS    Default query class, defaults to IN. May also be CH [default: IN]
      -c TCOUNT        Number of concurrent traffic generators per process [default: 10]
      -d DELAY_MS      ms delay between each traffic generator's query [default: 1]
      -q QCOUNT        Number of queries to send every DELAY ms [default: 10]
      -l LIMIT_SECS    Limit traffic generation to N seconds, 0 is unlimited [default: 0]
      -t TIMEOUT_SECS  Query timeout in seconds [default: 3]
      -n LOOP          Loop LOOP times through record list, 0 is unlimited [default: 0]
      -Q QPS           Rate limit to a maximum of QPS, 0 is no limit [default: 0]
      --qps-flow SPEC  Change rate limit over time, format: QPS,MS;QPS,MS;...
      -r RECORD        The base record to use as the DNS query for generators [default: test.com]
      -T QTYPE         The query type to use for generators [default: A]
      -f FILE          Read records from FILE, one per row, QNAME TYPE
      -p PORT          Which port to flame [defaults: 53, 853 for tcptls]
      -F FAMILY        Internet family (inet/inet6) [default: inet]
      -P PROTOCOL      Protocol to use (udp/tcp/tcptls/quic) [default: udp]
      -g GENERATOR     Generate queries with the given generator [default: static]
      -o FILE          Metrics output file, JSON format.
      -v VERBOSITY     How verbose output should be, 0 is silent [default: 1]
      -R               Randomize the query list before sending [default: false]
      --dnssec         Set DO flag in EDNS.

     Generators:

       Using generator modules you can craft the type of packet or query which is sent.

       Specify generator arguments by passing in KEY=VAL pairs, where the KEY is a specific configuration
       key interpreted by the generator as specified below in caps (although keys are not case sensitive).

       static                  The basic static generator, used by default, has a single qname/qtype
                               which you can set with -r and -T. There are no KEYs for this generator.

       file                    The basic file generator, used with -f, reads in one qname/qtype pair
                               per line in the file. There are no KEYs for this generator.

       numberqname             Synthesize qnames with random numbers, between [LOW, HIGH], at zone specified with -r

                    LOW        An integer representing the lowest number queried, default 0
                    HIGH       An integer representing the highest number queried, default 100000

       randompkt               Generate COUNT randomly generated packets, of random size [1,SIZE]

                    COUNT      An integer representing the number of packets to generate, default 1000
                    SIZE       An integer representing the maximum size of the random packet, default 600

       randomqname             Generate COUNT queries of randomly generated QNAME's (including nulls) of random length
                               [1,SIZE], at base zone specified with -r

                    COUNT      An integer representing the number of queries to generate, default 1000
                    SIZE       An integer representing the maximum length of the random qname, default 255

       randomlabel             Generate COUNT queries in base zone, each with LBLCOUNT random labels of size [1,LBLSIZE]
                               Use -r to set the base zone to create the labels in. Queries will have a random QTYPE
                               from the most popular set.

                    COUNT      An integer representing the number of queries to generate, default 1000
                    LBLSIZE    An integer representing the maximum length of a single label, default 10
                    LBLCOUNT   An integer representing the maximum number of labels in the qname, default 5


     Generator Example:
        flame target.test.com -T ANY -g randomlabel lblsize=10 lblcount=4 count=1000

)";

/**
 * the QUIC context
 */
static quicly_context_t ctx;
/**
 * CID seed
 */
static quicly_cid_plaintext_t next_cid;

static int read_stdin(quicly_conn_t *conn)
{
    quicly_stream_t *stream0;
    char buf[4096];
    size_t rret;

    if ((stream0 = quicly_get_stream(conn, 0)) == NULL || !quicly_sendstate_is_open(&stream0->sendstate))
        return 0;

    while ((rret = read(0, buf, sizeof(buf))) == -1 && errno == EINTR)
        ;
    if (rret == 0) {
        /* stdin closed, close the send-side of stream0 */
        quicly_streambuf_egress_shutdown(stream0);
        return 0;
    } else {
        /* write data to send buffer */
        quicly_streambuf_egress_write(stream0, buf, rret);
        return 1;
    }
}

void parse_flowspec(std::string spec, std::queue<std::pair<uint64_t, uint64_t>> &result, int verbosity)
{

    std::vector<std::string> groups = split(spec, ';');
    for (unsigned i = 0; i < groups.size(); i++) {
        std::vector<std::string> nums = split(groups[i], ',');
        if (verbosity > 1) {
            std::cout << "adding QPS flow: " << nums[0] << "qps, " << nums[1] << "ms" << std::endl;
        }
        result.push(std::make_pair(std::stol(nums[0]), std::stol(nums[1])));
    }
}

void flow_change(std::queue<std::pair<uint64_t, uint64_t>> qps_flow,
    std::shared_ptr<TokenBucket> rl,
    int verbosity)
{
    auto flow = qps_flow.front();
    qps_flow.pop();
    if (verbosity) {
        if (qps_flow.size()) {
            std::cout << "QPS flow now " << flow.first << " for " << flow.second << "ms, flows left: "
                      << qps_flow.size() << std::endl;
        } else {
            std::cout << "QPS flow now " << flow.first << " until completion" << std::endl;
        }
    }
    *rl = TokenBucket(flow.first, flow.first);
    if (qps_flow.size() == 0)
        return;
    auto loop = uvw::Loop::getDefault();
    auto qps_timer = loop->resource<uvw::TimerHandle>();
    qps_timer->on<uvw::TimerEvent>([qps_flow, rl, verbosity](const auto &event, auto &handle) {
        handle.stop();
        flow_change(qps_flow, rl, verbosity);
    });
    qps_timer->start(uvw::TimerHandle::Time{flow.second}, uvw::TimerHandle::Time{0});
}

bool arg_exists(const char *needle, int argc, char *argv[])
{
    for (int i = 0; i < argc; i++) {
        if (std::string(needle) == std::string(argv[i])) {
            return true;
        }
    }
    return false;
}

static void process_msg(quicly_conn_t **conn, struct msghdr *msg, size_t dgram_len)
{
    size_t off, packet_len;

    /* split UDP datagram into multiple QUIC packets */
    for (off = 0; off < dgram_len; off += packet_len) {
        quicly_decoded_packet_t decoded;
        if ((packet_len = quicly_decode_packet(&ctx, &decoded, (uint8_t*)msg->msg_iov[0].iov_base + off, dgram_len - off)) == SIZE_MAX)
            return;
        /* TODO match incoming packets to connections, handle version negotiation, rebinding, retry, etc. */
        if (*conn != NULL) {
            /* let the current connection handle ingress packets */
            quicly_receive(*conn, &decoded);
        } else {
            /* assume that the packet is a new connection */
            quicly_accept(conn, &ctx, (struct sockaddr*)msg->msg_name, msg->msg_namelen, &decoded, ptls_iovec_init(NULL, 0), &next_cid, NULL);
        }
    }
}

static int send_one(int fd, quicly_datagram_t *p)
{
    struct iovec vec = {.iov_base = p->data.base, .iov_len = p->data.len};
    struct msghdr mess = {.msg_name = &p->sa, .msg_namelen = p->salen, .msg_iov = &vec, .msg_iovlen = 1};
    int ret;

    while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR)
        ;
    return ret;
}

static int run_loop(int fd, quicly_conn_t *conn, int (*stdin_read_cb)(quicly_conn_t *conn))
{
    while (1) {

        /* wait for sockets to become readable, or some event in the QUIC stack to fire */
        fd_set readfds;
        struct timeval *tv, tvbuf;
        do {
            if (conn != NULL) {
                int64_t timeout_msec = quicly_get_first_timeout(conn) - ctx.now->cb(ctx.now);
                if (timeout_msec <= 0) {
                    tvbuf.tv_sec = 0;
                    tvbuf.tv_usec = 0;
                } else {
                    tvbuf.tv_sec = timeout_msec / 1000;
                    tvbuf.tv_usec = timeout_msec % 1000 * 1000;
                }
                tv = &tvbuf;
            } else {
                tv = NULL;
            }
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
            /* we want to read input from stdin */
            if (stdin_read_cb != NULL)
                FD_SET(0, &readfds);
        } while (select(fd + 1, &readfds, NULL, NULL, tv) == -1 && errno == EINTR);

        /* read the QUIC fd */
        if (FD_ISSET(fd, &readfds)) {
            uint8_t buf[4096];
            struct sockaddr_storage sa;
            struct iovec vec = {.iov_base = buf, .iov_len = sizeof(buf)};
            struct msghdr msg = {.msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = &vec, .msg_iovlen = 1};
            ssize_t rret;
            while ((rret = recvmsg(fd, &msg, 0)) <= 0 && errno == EINTR)
                ;
            if (rret > 0)
                process_msg(&conn, &msg, rret);
        }

        /* read stdin, send the input to the active stram */
        if (FD_ISSET(0, &readfds)) {
            assert(stdin_read_cb != NULL);
            if (!(*stdin_read_cb)(conn))
                stdin_read_cb = NULL;
        }

        /* send QUIC packets, if any */
        if (conn != NULL) {
            quicly_datagram_t *dgrams[16];
            size_t num_dgrams = sizeof(dgrams) / sizeof(dgrams[0]);
            int ret = quicly_send(conn, dgrams, &num_dgrams);
            switch (ret) {
                case 0: {
                    size_t i;
                    for (i = 0; i != num_dgrams; ++i) {
                        send_one(fd, dgrams[i]);
                        ctx.packet_allocator->free_packet(ctx.packet_allocator, dgrams[i]);
                    }
                } break;
                case QUICLY_ERROR_FREE_CONNECTION:
                    /* connection has been closed, free, and exit when running as a client */
                    quicly_free(conn);
                    conn = NULL;
                    return 0;
                default:
                    fprintf(stderr, "quicly_send returned %d\n", ret);
                    return 1;
            }
        }
    }

    return 0;
}

static int run_client(int fd, const char *host, struct sockaddr *sa, socklen_t salen)
{
    quicly_conn_t *conn;
    int ret;

    /* initiate a connection, and open a stream */
    if ((ret = quicly_connect(&conn, &ctx, host, sa, salen, &next_cid, NULL, NULL)) != 0) {
        fprintf(stderr, "quicly_connect failed:%d\n", ret);
        return 1;
    }
    quicly_stream_t *stream; /* we retain the opened stream via the on_stream_open callback */
    quicly_open_stream(conn, &stream, 0);

    /* enter the event loop with a connection object */
    return run_loop(fd, conn, read_stdin);
}


int main(int argc, char *argv[])
{

    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,           // show help if requested
        FLAME_VERSION); // version string

    if (args["-v"].asLong() > 3) {
        for (auto const &arg : args) {
            std::cout << arg.first << ": " << arg.second << std::endl;
        }
    }

    auto loop = uvw::Loop::getDefault();

    auto sigint = loop->resource<uvw::SignalHandle>();
    auto sigterm = loop->resource<uvw::SignalHandle>();
    std::shared_ptr<uvw::TimerHandle> run_timer;
    std::shared_ptr<uvw::TimerHandle> qgen_loop_timer;

    std::string output_file;
    if (args["-o"]) {
        output_file = args["-o"].asString();
    }

    // these defaults change based on protocol
    long s_delay = args["-d"].asLong();
    long b_count = args["-q"].asLong();
    long c_count = args["-c"].asLong();

    Protocol proto{Protocol::UDP};
    if (args["-P"].asString() == "tcp" || args["-P"].asString() == "tcptls") {
        proto = (args["-P"].asString() == "tcptls") ? Protocol::TCPTLS : Protocol::TCP;
        if (!arg_exists("-d", argc, argv))
            s_delay = 1000;
        if (!arg_exists("-q", argc, argv))
            b_count = 100;
        if (!arg_exists("-c", argc, argv))
            c_count = 30;
    } else if (args["-P"].asString() == "udp") {
        proto = Protocol::UDP;
    } else if (args["-P"].asString() == "quic") {
        proto = Protocol::QUIC;
    } else {
        std::cerr << "protocol must be 'udp', 'quic', 'tcp' or 'tcptls'" << std::endl;
        return 1;
    }

    if (!args["-p"]) {
        if (proto == Protocol::TCPTLS) {
            args["-p"] = std::string("853");
        }
        else if (proto == Protocol::QUIC) {
            args["-p"] = std::string("784");
        }
        else {
            args["-p"] = std::string("53");
        }
    }

    auto runtime_limit = args["-l"].asLong();

    auto request = loop->resource<uvw::GetAddrInfoReq>();
    auto target_resolved = request->addrInfoSync(args["TARGET"].asString(), args["-p"].asString());
    if (!target_resolved.first) {
        std::cerr << "unable to resolve target address: " << args["TARGET"].asString() << std::endl;
        return 1;
    }

    auto family_s = args["-F"].asString();
    int family{0};
    uvw::Addr addr{};
    if (family_s == "inet") {
        family = AF_INET;
    } else if (family_s == "inet6") {
        family = AF_INET6;
    } else {
        std::cerr << "internet family must be 'inet' or 'inet6'" << std::endl;
        return 1;
    }

    addrinfo *node{target_resolved.second.get()};
    while (node && node->ai_family != family) {
        node = node->ai_next;
    }
    if (!node) {
        std::cerr << "name did not resolve to valid IP address for this inet family" << std::endl;
        return 1;
    }

    if (family == AF_INET) {
        addr = uvw::details::address<uvw::IPv4>((struct sockaddr_in *)node->ai_addr);
    } else if (family == AF_INET6) {
        addr = uvw::details::address<uvw::IPv6>((struct sockaddr_in6 *)node->ai_addr);
    }

    auto config = std::make_shared<Config>(
        args["-v"].asLong(),
        output_file,
        args["-Q"].asLong());

    std::shared_ptr<QueryGenerator> qgen;
    try {
        if (args["-f"]) {
            qgen = std::make_shared<FileQueryGenerator>(config, args["-f"].asString());
        } else if (args["-g"] && args["-g"].asString() == "numberqname") {
            qgen = std::make_shared<NumberNameQueryGenerator>(config);
        } else if (args["-g"] && args["-g"].asString() == "randompkt") {
            qgen = std::make_shared<RandomPktQueryGenerator>(config);
        } else if (args["-g"] && args["-g"].asString() == "randomqname") {
            qgen = std::make_shared<RandomQNameQueryGenerator>(config);
        } else if (args["-g"] && args["-g"].asString() == "randomlabel") {
            qgen = std::make_shared<RandomLabelQueryGenerator>(config);
        } else {
            qgen = std::make_shared<StaticQueryGenerator>(config);
        }
        qgen->set_args(args["GENOPTS"].asStringList());
        qgen->set_qclass(args["--class"].asString());
        qgen->set_loops(args["-n"].asLong());
        qgen->set_dnssec(args["--dnssec"].asBool());
        qgen->set_qname(args["-r"].asString());
        qgen->set_qtype(args["-T"].asString());
        qgen->init();
    } catch (const std::exception &e) {
        std::cerr << "generator error: " << e.what() << std::endl;
        return 1;
    }

    if (args["-R"].asBool()) {
        qgen->randomize();
    }

    std::string cmdline{};
    for (int i = 0; i < argc; i++) {
        cmdline.append(argv[i]);
        if (i != argc - 1) {
            cmdline.push_back(' ');
        }
    }
    auto metrics_mgr = std::make_shared<MetricsMgr>(loop, config, cmdline);

    std::queue<std::pair<uint64_t, uint64_t>> qps_flow;
    std::shared_ptr<TokenBucket> rl;
    if (config->rate_limit()) {
        rl = std::make_shared<TokenBucket>(config->rate_limit(), config->rate_limit());
    } else if (args["--qps-flow"]) {
        rl = std::make_shared<TokenBucket>();
        parse_flowspec(args["--qps-flow"].asString(), qps_flow, config->verbosity());
        flow_change(qps_flow, rl, config->verbosity());
    }

    auto traf_config = std::make_shared<TrafGenConfig>();
    traf_config->batch_count = b_count;
    traf_config->family = family;
    traf_config->target_address = addr.ip;
    traf_config->port = static_cast<unsigned int>(args["-p"].asLong());
    traf_config->s_delay = s_delay;
    traf_config->protocol = proto;
    traf_config->r_timeout = args["-t"].asLong();

    std::vector<std::shared_ptr<TrafGen>> throwers;
    for (auto i = 0; i < c_count; i++) {
        throwers.push_back(std::make_shared<TrafGen>(loop,
            metrics_mgr->create_trafgen_metrics(),
            config,
            traf_config,
            qgen,
            rl));
        throwers[i]->start();
    }

    auto have_in_flight = [&throwers]() {
        for (const auto &i : throwers) {
            if (i->in_flight_cnt()) {
                return true;
            }
        }
        return false;
    };

    auto shutdown = [&]() {
        sigint->stop();
        sigterm->stop();
        if (run_timer.get())
            run_timer->stop();
        if (qgen_loop_timer.get())
            qgen_loop_timer->stop();
        for (auto &t : throwers) {
            t->stop();
        }
        metrics_mgr->stop();
        if (have_in_flight() && config->verbosity()) {
            std::cout << "stopping, waiting up to " << traf_config->r_timeout << "s for in flight to finish..." << std::endl;
        }
    };

    auto stop_traffic = [&](uvw::SignalEvent &, uvw::SignalHandle &) {
        shutdown();
    };

    if (runtime_limit != 0) {
        run_timer = loop->resource<uvw::TimerHandle>();
        run_timer->on<uvw::TimerEvent>([&shutdown](const auto &, auto &) { shutdown(); });
        run_timer->start(uvw::TimerHandle::Time{runtime_limit * 1000}, uvw::TimerHandle::Time{0});
    }

    if (qgen->loops()) {
        qgen_loop_timer = loop->resource<uvw::TimerHandle>();
        qgen_loop_timer->on<uvw::TimerEvent>([&qgen, &shutdown](const auto &, auto &) {
            if (qgen->finished()) {
                shutdown();
            } });
        qgen_loop_timer->start(uvw::TimerHandle::Time{500}, uvw::TimerHandle::Time{500});
    }

    sigint->on<uvw::SignalEvent>(stop_traffic);
    sigint->start(SIGINT);

    sigterm->on<uvw::SignalEvent>(stop_traffic);
    sigterm->start(SIGTERM);

    if (config->verbosity()) {
        std::cout << "flaming target " << args["TARGET"] << " (" << traf_config->target_address << ") on port "
                  << args["-p"].asLong()
                  << " with " << c_count << " concurrent generators, each sending " << b_count
                  << " queries every " << s_delay << "ms on protocol " << args["-P"].asString()
                  << std::endl;
        std::cout << "query generator [" << qgen->name() << "] contains " << qgen->size() << " record(s)" << std::endl;
        if (args["-R"].asBool()) {
            std::cout << "query list randomized" << std::endl;
        }
    }

    metrics_mgr->start();
    loop->run();

    // break from loop with ^C or timer
    loop = nullptr;

    // when loop is complete, finalize metrics
    metrics_mgr->finalize();

    return 0;
}
