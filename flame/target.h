// Copyright 2020 NSONE, Inc
// Copyright 2025 Flamethrower Contributors

#pragma once

#include <string>

#include "addr.h"

#include <urlparse.h>

struct Target {
    urlparse_url parsed;
    flame::socket_address address;
    std::string uri;
};
