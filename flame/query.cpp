// Copyright 2017 NSONE, Inc

#include "query.h"
#include "utils.h"
#include <algorithm>
#include <cctype>
#include <climits>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <stdexcept>

#include <ldns/rbtree.h>

#include <ldns/dname.h>
#include <ldns/host2wire.h>
#include <ldns/wire2host.h>

#include <arpa/inet.h>
#include <netinet/in.h>

// EDNS buffer size to avoid fragmentation on IPv6
static constexpr uint16_t EDNS_BUFFER_SIZE = 1232;

ldns_rr_type QueryGenerator::cvt_qtype(const std::string &t)
{

    ldns_rr_type qtype;
    std::string qt(t);
    std::transform(qt.begin(), qt.end(), qt.begin(), ::toupper);

    if (qt == "A") {
        qtype = LDNS_RR_TYPE_A;
    } else if (qt == "AAAA") {
        qtype = LDNS_RR_TYPE_AAAA;
    } else if (qt == "SOA") {
        qtype = LDNS_RR_TYPE_SOA;
    } else if (qt == "PTR") {
        qtype = LDNS_RR_TYPE_AAAA;
    } else if (qt == "TXT") {
        qtype = LDNS_RR_TYPE_TXT;
    } else if (qt == "ANY") {
        qtype = LDNS_RR_TYPE_ANY;
    } else if (qt == "CNAME") {
        qtype = LDNS_RR_TYPE_CNAME;
    } else if (qt == "MX") {
        qtype = LDNS_RR_TYPE_MX;
    } else if (qt == "NS") {
        qtype = LDNS_RR_TYPE_NS;
    } else if (qt == "SRV") {
        qtype = LDNS_RR_TYPE_SRV;
    } else if (qt == "SPF") {
        qtype = LDNS_RR_TYPE_SPF;
    } else if (qt == "A6") {
        qtype = LDNS_RR_TYPE_A6;
    } else if (qt == "CAA") {
        qtype = LDNS_RR_TYPE_CAA;
    } else if (qt == "CERT") {
        qtype = LDNS_RR_TYPE_CERT;
    } else if (qt == "AFSDB") {
        qtype = LDNS_RR_TYPE_AFSDB;
    } else if (qt == "ALIAS") {
        // No idea what to do with this one, I guess A or AAAA but technically we support ALIAS pointing to anything I think.
        throw std::runtime_error("unimplemented QTYPE: [" + qt + "]");
    } else if (qt == "DNAME") {
        qtype = LDNS_RR_TYPE_DNAME;
    } else if (qt == "HINFO") {
        qtype = LDNS_RR_TYPE_HINFO;
    } else if (qt == "NAPTR") {
        qtype = LDNS_RR_TYPE_NAPTR;
    } else if (qt == "DS") {
        qtype = LDNS_RR_TYPE_DS;
    } else if (qt == "RP") {
        qtype = LDNS_RR_TYPE_RP;
    } else {
        throw std::runtime_error("unimplemented QTYPE: [" + qt + "]");
    }

    return qtype;
}

bool QueryGenerator::finished()
{

    bool _finished{false};
    if (_loops) {
        _finished = (_reqs / _wire_buffers.size() >= _loops);
    }
    return _finished;
}

void QueryGenerator::randomize()
{
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(_wire_buffers.begin(), _wire_buffers.end(), g);
}

void QueryGenerator::set_args(const std::vector<std::string> &args)
{

    // check for key/val pairs
    bool have_kv{false};
    bool all_kv{true};
    for (auto arg : args) {
        if (arg.find('=') != std::string::npos) {
            have_kv = true;
        } else {
            all_kv = false;
        }
    }

    // if we have none, we will do positional args for backwards compat
    // UNLESS we have no generator arguments at all, in which case KEYVAL may use defaults
    if (have_kv && !all_kv) {
        throw std::runtime_error("mixed positional and key/val generator arguments are not supported");
    }

    _args_fmt = (args.size() == 0 || have_kv) ? GeneratorArgFmt::KEYVAL : GeneratorArgFmt::POSITIONAL;

    if (_args_fmt == GeneratorArgFmt::POSITIONAL) {
        _positional_args = args;
        if (_config->verbosity() > 1) {
            std::cerr << _positional_args.size() << " positional generator arguments" << std::endl;
        }
    } else {
        for (auto arg : args) {
            std::vector<std::string> vals = split(arg, '=');
            if (vals.size() != 2) {
                throw std::runtime_error("invalid key/value pair");
            }
            std::transform(vals[0].begin(), vals[0].end(), vals[0].begin(), ::toupper);
            _kv_args[vals[0]] = vals[1];
        }
        if (_config->verbosity() > 1) {
            std::cerr << _kv_args.size() << " key/value generator arguments" << std::endl;
        }
    }
}

QueryGenerator::QueryTpt QueryGenerator::next_base64url(uint16_t id)
{
    WireTpt w = _wire_buffers[_reqs++ % _wire_buffers.size()];
    size_t len{w.second};
    auto buf = std::make_unique<char[]>(len);
    memcpy(buf.get(), w.first, w.second);
    uint16_t _id = ntohs(id);
    memcpy(buf.get(), &_id, sizeof(_id));
    std::string encoded = base64_encode((unsigned char*) buf.get(), len);
    size_t encoded_len = encoded.size();
    auto encoded_buf = std::make_unique<char []>(encoded_len);
    memcpy(encoded_buf.get(), encoded.c_str(), encoded_len);
    return std::make_tuple(std::move(encoded_buf), encoded_len);
}

QueryGenerator::QueryTpt QueryGenerator::next_tcp(const std::vector<uint16_t> &id_list)
{

    // get total len
    size_t total_len{0};
    auto r = _reqs;
    for ([[maybe_unused]] auto id : id_list) {
        // include 2 byte size required in tcp dns
        total_len += 2 + _wire_buffers[r++ % _wire_buffers.size()].second;
    }

    size_t offset{0};
    auto buf = std::make_unique<char[]>(total_len);
    for (auto id : id_list) {
        WireTpt w = _wire_buffers[_reqs++ % _wire_buffers.size()];
        // write pkt len
        uint16_t plen = htons(w.second);
        memcpy(buf.get() + offset, &plen, sizeof(plen));
        // write wire
        memcpy(buf.get() + 2 + offset, w.first, w.second);
        // write id requested
        uint16_t _id = ntohs(id);
        memcpy(buf.get() + 2 + offset, &_id, sizeof(_id));
        offset += w.second + 2;
    }
    return std::make_tuple(std::move(buf), total_len);
}

QueryGenerator::QueryTpt QueryGenerator::next_udp(uint16_t id)
{

    WireTpt w = _wire_buffers[_reqs++ % _wire_buffers.size()];
    size_t len{w.second};
    auto buf = std::make_unique<char[]>(len);
    // write wire
    memcpy(buf.get(), w.first, w.second);
    // write id requested
    uint16_t _id = ntohs(id);
    memcpy(buf.get(), &_id, sizeof(_id));
    return std::make_tuple(std::move(buf), len);
}

QueryGenerator::~QueryGenerator()
{
    for (auto i : _wire_buffers) {
        free(i.first);
    }
}

static ldns_pkt *new_query(const char *name, size_t name_len, bool name_bin,
    ldns_rr_type rr_type, ldns_rr_class rr_class,
    uint16_t flags)
{
    ldns_rdf *rr_name = nullptr;

    if (name_bin) {
        // cap the length to max label length
        name_len = std::min<size_t>(name_len, LDNS_MAX_LABELLEN);

        // construct binary name
        uint8_t bin[name_len + 2];
        bin[0] = name_len;
        memmove(&bin[1], name, name_len);
        bin[sizeof(bin) - 1] = 0x00;

        rr_name = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME, sizeof(bin), bin);
    } else {
        rr_name = ldns_dname_new_frm_str(name);
    }

    if (!rr_name) {
        return nullptr;
    }

    if (rr_type == 0) {
        rr_type = LDNS_RR_TYPE_A;
    }
    if (rr_class == 0) {
        rr_class = LDNS_RR_CLASS_IN;
    }

    ldns_pkt *packet = ldns_pkt_query_new(rr_name, rr_type, rr_class, flags);
    if (!packet) {
        ldns_rdf_deep_free(rr_name);
        return nullptr;
    }

    return packet;
}

void QueryGenerator::new_rec(uint8_t **dest, size_t *dest_len, const char *qname, size_t len,
    const std::string &qtype, const std::string &prefix, bool binary, uint16_t id)
{

    ldns_enum_rr_class qclass;
    if (_qclass == "CH") {
        qclass = LDNS_RR_CLASS_CH;
    } else {
        qclass = LDNS_RR_CLASS_IN;
    }

    ldns_pkt *query = new_query(qname, len, binary, cvt_qtype(qtype), qclass, LDNS_RD);
    if (!query) {
        throw std::runtime_error("failed to create wire packet on [" + qtype + " " + std::string(qname) + "]");
    }

    if (_config->verbosity() >= 2 && _wire_buffers.size() < 10) {
        std::cerr << name() << ": push \"";
        if (!binary) {
            std::cerr << qname;
        } else {
            std::cerr << std::setfill('0');
            for (size_t i = 0; i < len; i++) {
                uint8_t c = qname[i];
                std::cerr << "\\" << std::setw(3) << static_cast<int>(c);
            }
        }
        std::cerr << ".\"\n";
    }

    if (id) {
        ldns_pkt_set_id(query, id);
    }

    ldns_pkt_set_edns_udp_size(query, EDNS_BUFFER_SIZE);
    ldns_pkt_set_edns_do(query, _dnssec);

    auto prefix_split = split(prefix, '/');
    if (prefix_split.size() == 2) {
        auto cidr = prefix_split[0];
        uint8_t mask = std::stoi(prefix_split[1]);

        bool ipv6 = false;
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;
        if (cidr.find(':') != std::string::npos) {
            ipv6 = true;
            inet_pton(AF_INET6, cidr.c_str(), &(sa6.sin6_addr));
        } else {
            inet_pton(AF_INET, cidr.c_str(), &(sa.sin_addr));
        }

        int numbytes = (mask + (CHAR_BIT - 1)) / CHAR_BIT;
        uint16_t optionlen = 4 + numbytes;

        // https://tools.ietf.org/html/rfc7871;
        int idx = 0;
        int buflen = optionlen + 4; // add 2 bytes each for option code/optionlen fields
        uint8_t *buf = (uint8_t *)malloc(buflen);
        buf[idx++] = 0x00; // option-code msb
        buf[idx++] = 0x08; // option-code lsb
        buf[idx++] = optionlen >> 16; //option-len msb
        buf[idx++] = optionlen & 0xFF; // option-len lsb
        buf[idx++] = 0x00; // family msb
        buf[idx++] = ipv6 ? 0x02 : 0x01; // family lsb
        buf[idx++] = mask; // source preflen
        buf[idx++] = 0x00; // scope preflen
        if (ipv6) {
            std::memcpy(&buf[idx], &sa6.sin6_addr, numbytes); // address
        } else {
            std::memcpy(&buf[idx], &sa.sin_addr, numbytes); // address
        }

        ldns_rdf *edns_data = ldns_rdf_new(LDNS_RDF_TYPE_UNKNOWN, buflen, buf);
        ldns_pkt_set_edns_data(query, edns_data);
    }

    ldns_pkt2wire(dest, query, dest_len);
    ldns_pkt_free(query);
}

void QueryGenerator::push_rec(const char *qname, size_t len, const std::string &qtype, bool binary)
{

    WireTpt w;
    new_rec(&w.first, &w.second, qname, len, qtype, "", binary, 0);
    _wire_buffers.push_back(w);
}

void QueryGenerator::push_rec(const std::string &qname, const std::string &qtype, const std::string &prefix, bool binary)
{
    WireTpt w;
    new_rec(&w.first, &w.second, qname.c_str(), qname.length(), qtype, prefix, binary, 0);
    _wire_buffers.push_back(w);
}

void QueryGenerator::push_rec(const std::string &qname, const std::string &qtype, bool binary)
{
    push_rec(qname.c_str(), qname.length(), qtype, binary);
}

void StaticQueryGenerator::init()
{
    push_rec(_qname, _qtype, false);
}

FileQueryGenerator::FileQueryGenerator(std::shared_ptr<Config> c,
    const std::string &fname)
    : QueryGenerator(c)
{
    std::ifstream file;
    std::string line;
    std::regex splitter("^[[:space:]]*([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]*([^[:space:]]+)?[[:space:]]*$");

    file.open(fname);
    if (!file.is_open()) {
        throw std::runtime_error("unable to open " + fname);
    }

    while (file.good()) {
        std::getline(file, line);
        std::smatch result;
        std::regex_match(line, result, splitter);
        if (result.size() == 3) {
            push_rec(std::move(result[1].str()), result[2].str(), false);
        } else if (result.size() == 4) {
            push_rec(std::move(result[1].str()), result[2].str(), result[3].str(), false);
        }
    }

    file.close();
}

void RandomPktQueryGenerator::init()
{
    std::ifstream file;
    file.open("/dev/urandom");
    if (!file.is_open()) {
        throw std::runtime_error("unable to open /dev/urandom");
    }

    // total number of queries
    long total{1000};

    // min and max byte counts
    int min_bytes{1};
    int max_bytes{600};

    if (_args_fmt == GeneratorArgFmt::POSITIONAL) {

        if (_positional_args.size() == 2) {
            total = std::stoi(_positional_args[0]);
            max_bytes = std::stoi(_positional_args[1]);
        } else {
            throw std::runtime_error("expected 2 positional generator arguments: COUNT SIZE");
        }

    } else {
        if (_kv_args.find("COUNT") != _kv_args.end()) {
            total = std::stoi(_kv_args["COUNT"]);
        }
        if (_kv_args.find("SIZE") != _kv_args.end()) {
            max_bytes = std::stoi(_kv_args["SIZE"]);
        }
    }

    if (total <= 0) {
        throw std::runtime_error("COUNT must be >= 1");
    }

    if (min_bytes < 1 || max_bytes > 65500) {
        throw std::runtime_error("SIZE out of range");
    }

    std::random_device rd;
    std::mt19937_64 generator{rd()};
    std::uniform_int_distribution<> dist{min_bytes, max_bytes};

    int bcount{1};
    _wire_buffers.reserve(total);
    for (int i = 0; i < total; i++) {
        bcount = dist(generator);
        char *buf = (char *)malloc(bcount);
        file.read(buf, bcount);
        _wire_buffers.push_back(WireTpt{(uint8_t *)buf, bcount});
    }

    file.close();
}

void RandomQNameQueryGenerator::init()
{

    std::ifstream file;
    file.open("/dev/urandom");
    if (!file.is_open()) {
        throw std::runtime_error("unable to open /dev/urandom");
    }

    // total number of queries
    long total{1000};

    // min and max byte counts
    int min_bytes{1};
    int max_bytes{LDNS_MAX_DOMAINLEN};

    if (_args_fmt == GeneratorArgFmt::POSITIONAL) {

        if (_positional_args.size() == 2) {
            total = std::stoi(_positional_args[0]);
            max_bytes = std::stoi(_positional_args[1]);
        } else {
            throw std::runtime_error("expected 2 positional generator arguments: COUNT SIZE");
        }

    } else {
        if (_kv_args.find("COUNT") != _kv_args.end()) {
            total = std::stoi(_kv_args["COUNT"]);
        }
        if (_kv_args.find("SIZE") != _kv_args.end()) {
            max_bytes = std::stoi(_kv_args["SIZE"]);
        }
    }

    if (total <= 0) {
        throw std::runtime_error("COUNT must be >= 1");
    }

    if (min_bytes < 1 || max_bytes > LDNS_MAX_DOMAINLEN) {
        throw std::runtime_error("SIZE out of range");
    }

    std::random_device rd;
    std::mt19937_64 generator{rd()};
    std::uniform_int_distribution<> dist{min_bytes, max_bytes};

    int bcount{1};
    _wire_buffers.reserve(total);
    for (int i = 0; i < total; i++) {
        bcount = dist(generator);
        char *buf = (char *)malloc(bcount);
        file.read(buf, bcount);
        push_rec(buf, bcount, _qtype, true);
        free(buf);
    }

    file.close();
}

void RandomLabelQueryGenerator::init()
{
    // total number of queries
    long total{1000};

    // min and max label char counts
    int min_len{2};
    int max_len{10};

    // random qtypes
    std::vector<std::string> r_qtypes = {"A", "AAAA", "NS", "CNAME", "MX", "TXT", "PTR", "SOA"};

    // label count
    int min_lbl{1};
    int max_lbl{5};

    if (_args_fmt == GeneratorArgFmt::POSITIONAL) {

        if (_positional_args.size() == 3) {
            total = std::stoi(_positional_args[0]);
            max_len = std::stoi(_positional_args[1]);
            max_lbl = std::stoi(_positional_args[2]);
        } else {
            throw std::runtime_error("expected 3 positional generator arguments: COUNT LBLSIZE LBLCOUNT");
        }

    } else {
        if (_kv_args.find("COUNT") != _kv_args.end()) {
            total = std::stoi(_kv_args["COUNT"]);
        }
        if (_kv_args.find("LBLSIZE") != _kv_args.end()) {
            max_len = std::stoi(_kv_args["LBLSIZE"]);
        }
        if (_kv_args.find("LBLCOUNT") != _kv_args.end()) {
            max_lbl = std::stoi(_kv_args["LBLCOUNT"]);
        }
    }

    if (total <= 0) {
        throw std::runtime_error("COUNT: total qnames to generate must be >= 1");
    }

    if (min_len < 1 || max_len > LDNS_MAX_LABELLEN) {
        throw std::runtime_error("LBLSIZE: size of labels must be between 1 and " + std::to_string(LDNS_MAX_LABELLEN));
    }

    if (min_lbl < 1 || max_lbl > LDNS_MAX_DOMAINLEN / 2) {
        throw std::runtime_error("LBLCOUNT: label count must be between 1 and " + std::to_string(LDNS_MAX_DOMAINLEN / 2));
    }

    std::random_device rd;
    std::mt19937_64 generator{rd()};
    std::uniform_int_distribution<> bdist{min_len, max_len};
    std::uniform_int_distribution<> ldist{min_lbl, max_lbl};
    std::uniform_int_distribution<> qtdist{0, static_cast<int>(r_qtypes.size() - 1)};

    std::vector<char> label_chars;
    for (char ch = 48; ch <= 57; ch++)
        label_chars.push_back(ch);
    for (char ch = 65; ch <= 90; ch++)
        label_chars.push_back(ch);
    for (char ch = 97; ch <= 122; ch++)
        label_chars.push_back(ch);
    label_chars.push_back('-');
    label_chars.push_back('_');
    std::uniform_int_distribution<> cdist{0, static_cast<int>(label_chars.size() - 1)};

    int bcount{1}; // characters in label
    int lcount{1}; // number of labels
    _wire_buffers.reserve(total);
    for (int i = 0; i < total; i++) {
        std::ostringstream qname;
        std::vector<std::string> label_parts;
        size_t total_qname_len{0};

        lcount = ldist(generator);
        auto _max = (LDNS_MAX_DOMAINLEN - lcount - _qname.length());
        for (int l = 0; l < lcount; l++) {
            bcount = bdist(generator);
            if (total_qname_len + bcount > _max)
                break;
            std::string label;
            for (int b = 0; b < bcount; b++) {
                label.push_back(label_chars[cdist(generator)]);
            }
            total_qname_len += bcount;
            label_parts.push_back(std::move(label));
        }
        // add base zone
        label_parts.push_back(_qname);
        // join for full qname
        std::copy(label_parts.begin(), label_parts.end(), std::ostream_iterator<std::string>(qname, "."));
        auto final_qname = qname.str();
        assert(final_qname.length() < LDNS_MAX_DOMAINLEN);
        push_rec(final_qname, r_qtypes[qtdist(generator)], false);
    }
}

void NumberNameQueryGenerator::init()
{
    // low and high numbers to choose from randomly
    int low{0};
    int high{100000};

    if (_args_fmt == GeneratorArgFmt::POSITIONAL) {

        if (_positional_args.size() == 2) {
            low = std::stoi(_positional_args[0]);
            high = std::stoi(_positional_args[1]);
        } else {
            throw std::runtime_error("expected 2 positional generator arguments: LOW HIGH");
        }

    } else {
        if (_kv_args.find("LOW") != _kv_args.end()) {
            low = std::stoi(_kv_args["LOW"]);
        }
        if (_kv_args.find("HIGH") != _kv_args.end()) {
            high = std::stoi(_kv_args["HIGH"]);
        }
    }

    if (low < 0 || low >= high) {
        throw std::runtime_error("LOW and HIGH must be 0 >= LOW > HIGH");
    }

    std::random_device rd;
    _generator = std::mt19937_64{rd()};
    _namedist = std::uniform_int_distribution<>{low, high};
}

QueryGenerator::QueryTpt NumberNameQueryGenerator::next_tcp(const std::vector<uint16_t> &id_list)
{

    throw std::runtime_error("tcp unsupported");
}

QueryGenerator::QueryTpt NumberNameQueryGenerator::next_udp(uint16_t id)
{

    uint8_t *buf;
    size_t buf_len;
    std::ostringstream qname;
    long n{0};

    n = _namedist(_generator);
    qname << n << '.' << _qname;

    new_rec(&buf, &buf_len, qname.str().c_str(), qname.str().length(), _qtype, "", false, id);

    auto ret_buf = std::make_unique<char[]>(buf_len);
    memcpy(ret_buf.get(), buf, buf_len);
    free(buf);

    return std::make_tuple(std::move(ret_buf), buf_len);
}
