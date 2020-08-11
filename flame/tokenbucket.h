
#pragma once

#include <chrono>
#include <uvw/loop.hpp>

class TokenBucket
{
public:
    TokenBucket()
        : _rate_qps(0)
        , _token_wallet(0)
        , _last_fill_ms(0)
    {
    }

    TokenBucket(const double rate)
        : _rate_qps(rate)
        , _token_wallet(0)
        , _last_fill_ms(0)
    {
    }

    bool consume(const uint64_t tokens, const uvw::Loop::Time now_ms)
    {
        if (_token_wallet < tokens) {
            if (_last_fill_ms.count() == 0) {
                _last_fill_ms = now_ms;
            } else if (now_ms > _last_fill_ms) {
                auto elapsed_ms = (now_ms - _last_fill_ms).count();
                double add = _rate_qps * ((double)elapsed_ms / 1000.0);
                if (_token_wallet + add >= tokens) {
                    _token_wallet += add;
                    _last_fill_ms = now_ms;
                }
            }
            if (_token_wallet < tokens) {
                return false;
            }
        }
        _token_wallet -= tokens;
        return true;
    }

private:
    double _rate_qps;
    double _token_wallet;
    // milliseconds, based on uv_now() http://docs.libuv.org/en/v1.x/loop.html#c.uv_now
    uvw::Loop::Time _last_fill_ms;
};
