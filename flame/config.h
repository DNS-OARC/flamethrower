// Copyright 2017 NSONE, Inc

#pragma once

#include <string>

class Config
{
private:
    std::string _output_file;
    int _verbosity{1};
    long _rate_limit{0};

public:
    Config(
        int verbosity,
        const std::string output_file,
        long rate_limit)
        : _output_file(output_file)
        , _verbosity(verbosity)
        , _rate_limit(rate_limit)
    {
    }

    int verbosity()
    {
        return _verbosity;
    }

    const std::string &output_file()
    {
        return _output_file;
    }

    long rate_limit()
    {
        return _rate_limit;
    }
};
