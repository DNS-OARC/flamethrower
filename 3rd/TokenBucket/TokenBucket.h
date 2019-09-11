
#pragma once

#include <chrono>
#include <uvw/loop.hpp>

class TokenBucket {
public:
    TokenBucket() : rate_qps_(0), token_wallet_(0), lastFill_ms_(0) {}

    TokenBucket(const uint64_t rate) : rate_qps_(rate), token_wallet_(0), lastFill_ms_(0) {}

    bool consume(const uint64_t tokens, const uvw::Loop::Time now_ms) {
        if (token_wallet_ < tokens) {
            if (lastFill_ms_.count() == 0) {
                lastFill_ms_ = now_ms;
            }
            else if (now_ms > lastFill_ms_) {
                auto elapsed_ms = (now_ms - lastFill_ms_).count();
                double add = (double)rate_qps_ * ((double)elapsed_ms / 1000.0);
                if (token_wallet_ + add >= tokens) {
                    token_wallet_ += add;
                    lastFill_ms_ = now_ms;
                }
            }
            if (token_wallet_ < tokens) {
                return false;
            }
        }
        token_wallet_ -= tokens;
        return true;
    }

private:
    uint64_t rate_qps_;
    uint64_t token_wallet_;
    // milliseconds, based on uv_now() http://docs.libuv.org/en/v1.x/loop.html#c.uv_now
    uvw::Loop::Time lastFill_ms_;
};
