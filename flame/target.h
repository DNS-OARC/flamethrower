#ifndef FLAMETHROWER_TARGET_H
#define FLAMETHROWER_TARGET_H

struct http_parser_url;

struct Target {
    http_parser_url* parsed;
    std::string address;
    std::string uri;
};

#endif //FLAMETHROWER_TARGET_H
