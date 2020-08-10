#pragma once

#include <chrono>
#include <uvw/loop.hpp>

class TokenBucket
{
    using milliseconds = std::chrono::milliseconds;

public:
    TokenBucket()
        : _rate_qps(0)
        , _token_wallet(0)
        , _last_fill(0)
    {
    }

    TokenBucket(const uint64_t rate_qps)
        : _rate_qps(rate_qps)
        , _token_wallet(0)
        , _last_fill(0)
    {
    }

    bool consume(const uint64_t tokens, std::chrono::milliseconds now)
    {
        if (_last_fill.count() == 0) {
            _token_wallet += _rate_qps;
            _last_fill = now;
        }

        if (tokens > _token_wallet) {
            auto elapsed = (now - _last_fill).count();
            if (elapsed > 1000) {
                uint64_t add = static_cast<double>(_rate_qps) * static_cast<double>(elapsed) / 1000.0;
                _token_wallet += add;
                _last_fill = now;
            }
        }

        if (tokens <= _token_wallet) {
            _token_wallet -= tokens;
            return true;
        }

        return false;
    }

private:
    uint64_t _rate_qps;
    uint64_t _token_wallet;
    milliseconds _last_fill;
};
