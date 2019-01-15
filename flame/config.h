// Copyright 2019 NSONE, Inc

#pragma once

#include <string>
#include <vector>

class Config
{
private:
    long _rate_limit{0};
    std::string _output_file;
    int _verbosity{1};

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
