#pragma once

#include <string>

#include <sys/socket.h>

#include <urlparse.h>

struct Target {
    urlparse_url parsed;
    sockaddr_storage address;
    std::string uri;
};
