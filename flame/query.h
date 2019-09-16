// Copyright 2017 NSONE, Inc

#pragma once

#include <chrono>
#include <exception>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <tuple>
#include <vector>

#include "base64.h"
#include "config.h"
#include <ldns/rr.h>

enum class GeneratorArgFmt {
    POSITIONAL,
    KEYVAL,
};

class Query
{
public:
    // XXX ip we send query to, so we can track mismatched ips
    // XXX qname we sent to ^
    std::chrono::high_resolution_clock::time_point send_time;
};

class QueryGenerator
{
public:
    using WireTpt = std::pair<uint8_t *, size_t>;

protected:
    unsigned long _loops{0};
    std::string _qclass;
    std::string _qname;
    std::string _qtype;
    bool _dnssec{false};
    std::vector<std::string> _positional_args;
    std::map<std::string, std::string> _kv_args;
    GeneratorArgFmt _args_fmt;

    std::shared_ptr<Config> _config;
    std::vector<WireTpt> _wire_buffers;
    unsigned long _reqs{0};
    ldns_rr_type cvt_qtype(const std::string &t);

    void new_rec(uint8_t **dest, size_t *dest_len, const char *qname, size_t len,
        const std::string &qtype, const std::string &prefix, bool binary, uint16_t id);
    void push_rec(const char *qname, size_t len, const std::string &qtype, bool binary);
    void push_rec(const std::string &qname, const std::string &qtype, const std::string &prefix, bool binary);
    void push_rec(const std::string &qname, const std::string &qtype, bool binary);

public:
    using QueryTpt = std::tuple<std::unique_ptr<char[]>, std::size_t>;

    QueryGenerator(std::shared_ptr<Config> c)
        : _config(c)
    {
    }
    virtual ~QueryGenerator();

    virtual void init() = 0;

    virtual QueryTpt next_base64url(uint16_t);
    virtual QueryTpt next_udp(uint16_t);
    virtual QueryTpt next_tcp(const std::vector<uint16_t> &);
    bool finished();

    virtual const char *name() = 0;

    virtual bool synthesizedQueries() = 0;

    void set_args(const std::vector<std::string> &args);

    void set_loops(unsigned long l)
    {
        _loops = l;
    }

    void set_qtype(const std::string &q)
    {
        _qtype = q;
    }

    void set_qclass(const std::string &q)
    {
        _qclass = q;
    }

    void set_qname(const std::string &q)
    {
        _qname = q;
    }

    void set_dnssec(bool d)
    {
        _dnssec = d;
    }

    unsigned long loops() const
    {
        return _loops;
    }

    const std::string &qtype() const
    {
        return _qtype;
    }

    const std::string &qclass() const
    {
        return _qclass;
    }

    const std::string &qname() const
    {
        return _qname;
    }

    bool dnssec() const
    {
        return _dnssec;
    }

    size_t size()
    {
        return _wire_buffers.size();
    }

    void randomize();
};

class StaticQueryGenerator : public QueryGenerator
{

public:
    StaticQueryGenerator(std::shared_ptr<Config> c)
        : QueryGenerator(c){};

    void init();

    const char *name()
    {
        return "static";
    }

    bool synthesizedQueries()
    {
        return false;
    }
};

class FileQueryGenerator : public QueryGenerator
{

public:
    FileQueryGenerator(std::shared_ptr<Config> c,
        const std::string &fname);

    void init()
    {
    }

    const char *name()
    {
        return "file";
    }
    bool synthesizedQueries()
    {
        return false;
    }
};

class RandomPktQueryGenerator : public QueryGenerator
{

public:
    RandomPktQueryGenerator(std::shared_ptr<Config> c)
        : QueryGenerator(c){};

    void init();

    const char *name()
    {
        return "randompkt";
    }
    bool synthesizedQueries()
    {
        return false;
    }
};

class RandomQNameQueryGenerator : public QueryGenerator
{

public:
    RandomQNameQueryGenerator(std::shared_ptr<Config> c)
        : QueryGenerator(c){};

    void init();

    const char *name()
    {
        return "randomqname";
    }
    bool synthesizedQueries()
    {
        return false;
    }
};

class RandomLabelQueryGenerator : public QueryGenerator
{

public:
    RandomLabelQueryGenerator(std::shared_ptr<Config> c)
        : QueryGenerator(c){};

    void init();

    const char *name()
    {
        return "randomlabel";
    }
    bool synthesizedQueries()
    {
        return false;
    }
};

class NumberNameQueryGenerator : public QueryGenerator
{

    std::mt19937_64 _generator;
    std::uniform_int_distribution<> _namedist;

public:
    NumberNameQueryGenerator(std::shared_ptr<Config> c)
        : QueryGenerator(c)
    {
    }

    void init();

    //QueryTpt next_base64url(uint16_t);
    QueryTpt next_udp(uint16_t);
    QueryTpt next_tcp(const std::vector<uint16_t> &);

    const char *name()
    {
        return "numberqname";
    }
    bool synthesizedQueries()
    {
        return true;
    }
};
