// Copyright 2025 Flamethrower Contributors

#include <cassert>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "proxy.h"

static int tests_run = 0;
static int tests_failed = 0;

#define RUN_TEST(func)                                         \
    do {                                                       \
        tests_run++;                                           \
        std::cout << "  " #func "... ";                        \
        try {                                                  \
            func();                                            \
            std::cout << "PASS" << std::endl;                  \
        } catch (const std::exception &e) {                    \
            tests_failed++;                                    \
            std::cout << "FAIL: " << e.what() << std::endl;    \
        } catch (...) {                                        \
            tests_failed++;                                    \
            std::cout << "FAIL: unknown exception" << std::endl; \
        }                                                      \
    } while (0)

#define ASSERT_EQ(a, b)                                            \
    do {                                                           \
        if ((a) != (b)) {                                          \
            throw std::runtime_error(                              \
                std::string("assertion failed: ") + #a " != " #b); \
        }                                                          \
    } while (0)

#define ASSERT_THROW(expr)                                              \
    do {                                                                \
        bool caught = false;                                            \
        try {                                                           \
            expr;                                                       \
        } catch (const std::exception &) {                              \
            caught = true;                                              \
        }                                                               \
        if (!caught)                                                    \
            throw std::runtime_error("expected exception from: " #expr); \
    } while (0)

static const unsigned char PPV2_SIGNATURE[] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

static ProxyInfo make_ipv4_info(const char *src_ip, uint16_t src_port,
    const char *dst_ip, uint16_t dst_port)
{
    ProxyInfo info{};
    info.enabled = true;
    info.family = AF_INET;

    auto *src = reinterpret_cast<sockaddr_in *>(&info.src_addr);
    src->sin_family = AF_INET;
    inet_pton(AF_INET, src_ip, &src->sin_addr);
    src->sin_port = htons(src_port);

    auto *dst = reinterpret_cast<sockaddr_in *>(&info.dst_addr);
    dst->sin_family = AF_INET;
    inet_pton(AF_INET, dst_ip, &dst->sin_addr);
    dst->sin_port = htons(dst_port);

    return info;
}

static ProxyInfo make_ipv6_info(const char *src_ip, uint16_t src_port,
    const char *dst_ip, uint16_t dst_port)
{
    ProxyInfo info{};
    info.enabled = true;
    info.family = AF_INET6;

    auto *src = reinterpret_cast<sockaddr_in6 *>(&info.src_addr);
    src->sin6_family = AF_INET6;
    inet_pton(AF_INET6, src_ip, &src->sin6_addr);
    src->sin6_port = htons(src_port);

    auto *dst = reinterpret_cast<sockaddr_in6 *>(&info.dst_addr);
    dst->sin6_family = AF_INET6;
    inet_pton(AF_INET6, dst_ip, &dst->sin6_addr);
    dst->sin6_port = htons(dst_port);

    return info;
}

// ===== generate_proxy_v2_header: signature and version =====

void test_header_signature()
{
    auto info = make_ipv4_info("192.168.1.1", 12345, "10.0.0.1", 53);
    auto header = generate_proxy_v2_header(info, Protocol::UDP);

    ASSERT_EQ(header.size() >= 16, true);
    ASSERT_EQ(memcmp(header.data(), PPV2_SIGNATURE, 12), 0);
}

void test_header_version_command()
{
    auto info = make_ipv4_info("192.168.1.1", 12345, "10.0.0.1", 53);
    auto header = generate_proxy_v2_header(info, Protocol::UDP);

    // version 2, PROXY command -> 0x21
    ASSERT_EQ((unsigned char)header[12], 0x21);
}

// ===== generate_proxy_v2_header: family/protocol byte =====

void test_ipv4_udp_family_protocol()
{
    auto info = make_ipv4_info("1.2.3.4", 1000, "5.6.7.8", 53);
    auto header = generate_proxy_v2_header(info, Protocol::UDP);

    // AF_INET=0x1, DGRAM=0x2 -> 0x12
    ASSERT_EQ((unsigned char)header[13], 0x12);
}

void test_ipv4_tcp_family_protocol()
{
    auto info = make_ipv4_info("1.2.3.4", 1000, "5.6.7.8", 53);
    auto header = generate_proxy_v2_header(info, Protocol::TCP);

    // AF_INET=0x1, STREAM=0x1 -> 0x11
    ASSERT_EQ((unsigned char)header[13], 0x11);
}

void test_ipv4_dot_family_protocol()
{
    auto info = make_ipv4_info("1.2.3.4", 1000, "5.6.7.8", 853);
    auto header = generate_proxy_v2_header(info, Protocol::DOT);

    // DoT uses TCP -> 0x11
    ASSERT_EQ((unsigned char)header[13], 0x11);
}

#ifdef DOH_ENABLE
void test_ipv4_doh_family_protocol()
{
    auto info = make_ipv4_info("1.2.3.4", 1000, "5.6.7.8", 443);
    auto header = generate_proxy_v2_header(info, Protocol::DOH);

    // DoH uses TCP -> 0x11
    ASSERT_EQ((unsigned char)header[13], 0x11);
}
#endif

void test_ipv6_udp_family_protocol()
{
    auto info = make_ipv6_info("2001:db8::1", 1000, "2001:db8::2", 53);
    auto header = generate_proxy_v2_header(info, Protocol::UDP);

    // AF_INET6=0x2, DGRAM=0x2 -> 0x22
    ASSERT_EQ((unsigned char)header[13], 0x22);
}

void test_ipv6_tcp_family_protocol()
{
    auto info = make_ipv6_info("2001:db8::1", 1000, "2001:db8::2", 53);
    auto header = generate_proxy_v2_header(info, Protocol::TCP);

    // AF_INET6=0x2, STREAM=0x1 -> 0x21
    ASSERT_EQ((unsigned char)header[13], 0x21);
}

void test_ipv6_dot_family_protocol()
{
    auto info = make_ipv6_info("::1", 1000, "::1", 853);
    auto header = generate_proxy_v2_header(info, Protocol::DOT);

    // DoT uses TCP -> 0x21
    ASSERT_EQ((unsigned char)header[13], 0x21);
}

#ifdef DOH_ENABLE
void test_ipv6_doh_family_protocol()
{
    auto info = make_ipv6_info("::1", 1000, "::1", 443);
    auto header = generate_proxy_v2_header(info, Protocol::DOH);

    // DoH uses TCP -> 0x21
    ASSERT_EQ((unsigned char)header[13], 0x21);
}
#endif

// ===== generate_proxy_v2_header: address length and total size =====

void test_ipv4_address_length()
{
    auto info = make_ipv4_info("1.2.3.4", 1000, "5.6.7.8", 53);
    auto header = generate_proxy_v2_header(info, Protocol::UDP);

    // IPv4: 4 + 4 + 2 + 2 = 12
    uint16_t addr_len;
    memcpy(&addr_len, &header[14], 2);
    ASSERT_EQ(ntohs(addr_len), 12);
}

void test_ipv4_total_size()
{
    auto info = make_ipv4_info("1.2.3.4", 1000, "5.6.7.8", 53);
    auto header = generate_proxy_v2_header(info, Protocol::TCP);

    // 16 fixed + 12 addresses = 28
    ASSERT_EQ(header.size(), (size_t)28);
}

void test_ipv6_address_length()
{
    auto info = make_ipv6_info("2001:db8::1", 1000, "2001:db8::2", 53);
    auto header = generate_proxy_v2_header(info, Protocol::TCP);

    // IPv6: 16 + 16 + 2 + 2 = 36
    uint16_t addr_len;
    memcpy(&addr_len, &header[14], 2);
    ASSERT_EQ(ntohs(addr_len), 36);
}

void test_ipv6_total_size()
{
    auto info = make_ipv6_info("2001:db8::1", 1000, "2001:db8::2", 53);
    auto header = generate_proxy_v2_header(info, Protocol::TCP);

    // 16 fixed + 36 addresses = 52
    ASSERT_EQ(header.size(), (size_t)52);
}

// ===== generate_proxy_v2_header: address and port encoding =====

void test_ipv4_addresses_and_ports()
{
    auto info = make_ipv4_info("192.168.1.100", 8080, "10.20.30.40", 53);
    auto header = generate_proxy_v2_header(info, Protocol::TCP);

    // Source IPv4 at offset 16
    struct in_addr src_addr, dst_addr;
    memcpy(&src_addr, &header[16], 4);
    memcpy(&dst_addr, &header[20], 4);

    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &dst_addr, dst_str, sizeof(dst_str));

    ASSERT_EQ(std::string(src_str), std::string("192.168.1.100"));
    ASSERT_EQ(std::string(dst_str), std::string("10.20.30.40"));

    // Source port at offset 24, dest port at offset 26
    uint16_t src_port, dst_port;
    memcpy(&src_port, &header[24], 2);
    memcpy(&dst_port, &header[26], 2);
    ASSERT_EQ(ntohs(src_port), 8080);
    ASSERT_EQ(ntohs(dst_port), 53);
}

void test_ipv6_addresses_and_ports()
{
    auto info = make_ipv6_info("2001:db8::1", 9999, "fe80::42", 853);
    auto header = generate_proxy_v2_header(info, Protocol::DOT);

    // Source IPv6 at offset 16 (16 bytes), dest at offset 32
    struct in6_addr src_addr, dst_addr;
    memcpy(&src_addr, &header[16], 16);
    memcpy(&dst_addr, &header[32], 16);

    char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &src_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET6, &dst_addr, dst_str, sizeof(dst_str));

    ASSERT_EQ(std::string(src_str), std::string("2001:db8::1"));
    ASSERT_EQ(std::string(dst_str), std::string("fe80::42"));

    // Source port at offset 48, dest port at offset 50
    uint16_t src_port, dst_port;
    memcpy(&src_port, &header[48], 2);
    memcpy(&dst_port, &header[50], 2);
    ASSERT_EQ(ntohs(src_port), 9999);
    ASSERT_EQ(ntohs(dst_port), 853);
}

// ===== generate_proxy_v2_header: error cases =====

void test_generate_invalid_family()
{
    ProxyInfo info{};
    info.enabled = true;
    info.family = AF_UNSPEC;
    ASSERT_THROW(generate_proxy_v2_header(info, Protocol::UDP));
}

// ===== parse_proxy_spec =====

void test_parse_ipv4_with_ports()
{
    auto info = parse_proxy_spec("127.0.0.1#8080-127.0.0.2#53", AF_INET);

    ASSERT_EQ(info.enabled, true);
    ASSERT_EQ(info.family, AF_INET);

    auto *src = reinterpret_cast<const sockaddr_in *>(&info.src_addr);
    auto *dst = reinterpret_cast<const sockaddr_in *>(&info.dst_addr);

    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src->sin_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &dst->sin_addr, dst_str, sizeof(dst_str));

    ASSERT_EQ(std::string(src_str), std::string("127.0.0.1"));
    ASSERT_EQ(std::string(dst_str), std::string("127.0.0.2"));
    ASSERT_EQ(ntohs(src->sin_port), 8080);
    ASSERT_EQ(ntohs(dst->sin_port), 53);
}

void test_parse_ipv4_without_ports()
{
    auto info = parse_proxy_spec("10.0.0.1-10.0.0.2", AF_INET);

    ASSERT_EQ(info.enabled, true);
    ASSERT_EQ(info.family, AF_INET);

    auto *src = reinterpret_cast<const sockaddr_in *>(&info.src_addr);
    auto *dst = reinterpret_cast<const sockaddr_in *>(&info.dst_addr);

    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src->sin_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &dst->sin_addr, dst_str, sizeof(dst_str));

    ASSERT_EQ(std::string(src_str), std::string("10.0.0.1"));
    ASSERT_EQ(std::string(dst_str), std::string("10.0.0.2"));
    ASSERT_EQ(ntohs(src->sin_port), 0);
    ASSERT_EQ(ntohs(dst->sin_port), 0);
}

void test_parse_ipv6_with_ports()
{
    auto info = parse_proxy_spec("[::1]#8080-[::1]#53", AF_INET6);

    ASSERT_EQ(info.enabled, true);
    ASSERT_EQ(info.family, AF_INET6);

    auto *src = reinterpret_cast<const sockaddr_in6 *>(&info.src_addr);
    auto *dst = reinterpret_cast<const sockaddr_in6 *>(&info.dst_addr);

    char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &src->sin6_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET6, &dst->sin6_addr, dst_str, sizeof(dst_str));

    ASSERT_EQ(std::string(src_str), std::string("::1"));
    ASSERT_EQ(std::string(dst_str), std::string("::1"));
    ASSERT_EQ(ntohs(src->sin6_port), 8080);
    ASSERT_EQ(ntohs(dst->sin6_port), 53);
}

void test_parse_ipv6_without_ports()
{
    auto info = parse_proxy_spec("[::1]-[::1]", AF_INET6);

    ASSERT_EQ(info.enabled, true);
    ASSERT_EQ(info.family, AF_INET6);

    auto *src = reinterpret_cast<const sockaddr_in6 *>(&info.src_addr);
    auto *dst = reinterpret_cast<const sockaddr_in6 *>(&info.dst_addr);

    ASSERT_EQ(ntohs(src->sin6_port), 0);
    ASSERT_EQ(ntohs(dst->sin6_port), 0);
}

// ===== parse_proxy_spec: auto-detect family =====

void test_parse_auto_detect_ipv4()
{
    auto info = parse_proxy_spec("127.0.0.1#80-127.0.0.2#53", AF_UNSPEC);

    ASSERT_EQ(info.enabled, true);
    ASSERT_EQ(info.family, AF_INET);

    auto *src = reinterpret_cast<const sockaddr_in *>(&info.src_addr);
    auto *dst = reinterpret_cast<const sockaddr_in *>(&info.dst_addr);

    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src->sin_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &dst->sin_addr, dst_str, sizeof(dst_str));

    ASSERT_EQ(std::string(src_str), std::string("127.0.0.1"));
    ASSERT_EQ(std::string(dst_str), std::string("127.0.0.2"));
    ASSERT_EQ(ntohs(src->sin_port), 80);
    ASSERT_EQ(ntohs(dst->sin_port), 53);
}

void test_parse_auto_detect_ipv6()
{
    auto info = parse_proxy_spec("[::1]#80-[::1]#53", AF_UNSPEC);

    ASSERT_EQ(info.enabled, true);
    ASSERT_EQ(info.family, AF_INET6);

    auto *src = reinterpret_cast<const sockaddr_in6 *>(&info.src_addr);
    auto *dst = reinterpret_cast<const sockaddr_in6 *>(&info.dst_addr);

    ASSERT_EQ(ntohs(src->sin6_port), 80);
    ASSERT_EQ(ntohs(dst->sin6_port), 53);
}

// ===== parse_proxy_spec: family mismatch =====

void test_parse_family_mismatch_v6_as_v4()
{
    ASSERT_THROW(parse_proxy_spec("[::1]-[::1]", AF_INET));
}

// ===== parse_proxy_spec: port boundaries =====

void test_parse_port_65535()
{
    auto info = parse_proxy_spec("127.0.0.1#65535-127.0.0.2#65535", AF_INET);
    auto *src = reinterpret_cast<const sockaddr_in *>(&info.src_addr);
    auto *dst = reinterpret_cast<const sockaddr_in *>(&info.dst_addr);
    ASSERT_EQ(ntohs(src->sin_port), 65535);
    ASSERT_EQ(ntohs(dst->sin_port), 65535);
}

void test_parse_port_zero_explicit()
{
    auto info = parse_proxy_spec("127.0.0.1#0-127.0.0.2#0", AF_INET);
    auto *src = reinterpret_cast<const sockaddr_in *>(&info.src_addr);
    auto *dst = reinterpret_cast<const sockaddr_in *>(&info.dst_addr);
    ASSERT_EQ(ntohs(src->sin_port), 0);
    ASSERT_EQ(ntohs(dst->sin_port), 0);
}

// ===== parse_proxy_spec: asymmetric ports =====

void test_parse_asymmetric_ports()
{
    auto info = parse_proxy_spec("127.0.0.1-127.0.0.2#53", AF_INET);
    auto *src = reinterpret_cast<const sockaddr_in *>(&info.src_addr);
    auto *dst = reinterpret_cast<const sockaddr_in *>(&info.dst_addr);
    ASSERT_EQ(ntohs(src->sin_port), 0);
    ASSERT_EQ(ntohs(dst->sin_port), 53);
}

// ===== parse_proxy_spec: roundtrip through header generation =====

void test_parse_roundtrip_ipv4()
{
    auto info = parse_proxy_spec("192.168.0.1#1234-10.0.0.1#5678", AF_INET);
    auto header = generate_proxy_v2_header(info, Protocol::TCP);

    ASSERT_EQ(header.size(), (size_t)28);
    ASSERT_EQ((unsigned char)header[13], 0x11); // TCPv4

    struct in_addr src_addr, dst_addr;
    memcpy(&src_addr, &header[16], 4);
    memcpy(&dst_addr, &header[20], 4);
    char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &dst_addr, dst_str, sizeof(dst_str));
    ASSERT_EQ(std::string(src_str), std::string("192.168.0.1"));
    ASSERT_EQ(std::string(dst_str), std::string("10.0.0.1"));

    uint16_t src_port, dst_port;
    memcpy(&src_port, &header[24], 2);
    memcpy(&dst_port, &header[26], 2);
    ASSERT_EQ(ntohs(src_port), 1234);
    ASSERT_EQ(ntohs(dst_port), 5678);
}

void test_parse_roundtrip_ipv6()
{
    auto info = parse_proxy_spec("[::1]#4321-[::1]#8765", AF_INET6);
    auto header = generate_proxy_v2_header(info, Protocol::UDP);

    ASSERT_EQ(header.size(), (size_t)52);
    ASSERT_EQ((unsigned char)header[13], 0x22); // UDPv6

    struct in6_addr src_addr, dst_addr;
    memcpy(&src_addr, &header[16], 16);
    memcpy(&dst_addr, &header[32], 16);
    char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &src_addr, src_str, sizeof(src_str));
    inet_ntop(AF_INET6, &dst_addr, dst_str, sizeof(dst_str));
    ASSERT_EQ(std::string(src_str), std::string("::1"));
    ASSERT_EQ(std::string(dst_str), std::string("::1"));

    uint16_t src_port, dst_port;
    memcpy(&src_port, &header[48], 2);
    memcpy(&dst_port, &header[50], 2);
    ASSERT_EQ(ntohs(src_port), 4321);
    ASSERT_EQ(ntohs(dst_port), 8765);
}

// ===== parse_proxy_spec: error cases =====

void test_parse_invalid_no_dash()
{
    ASSERT_THROW(parse_proxy_spec("127.0.0.1", AF_INET));
}

void test_parse_invalid_empty()
{
    ASSERT_THROW(parse_proxy_spec("", AF_INET));
}

void test_parse_invalid_address()
{
    ASSERT_THROW(parse_proxy_spec("not_valid-also_not_valid", AF_INET));
}

void test_parse_invalid_too_many_parts()
{
    ASSERT_THROW(parse_proxy_spec("1.2.3.4-5.6.7.8-9.10.11.12", AF_INET));
}

// ===== ProxyInfo defaults =====

void test_default_proxy_info()
{
    ProxyInfo info{};
    ASSERT_EQ(info.enabled, false);
    ASSERT_EQ(info.family, 0);
}

int main()
{
    std::cout << "=== generate_proxy_v2_header ===" << std::endl;
    RUN_TEST(test_header_signature);
    RUN_TEST(test_header_version_command);
    RUN_TEST(test_ipv4_udp_family_protocol);
    RUN_TEST(test_ipv4_tcp_family_protocol);
    RUN_TEST(test_ipv4_dot_family_protocol);
#ifdef DOH_ENABLE
    RUN_TEST(test_ipv4_doh_family_protocol);
#endif
    RUN_TEST(test_ipv6_udp_family_protocol);
    RUN_TEST(test_ipv6_tcp_family_protocol);
    RUN_TEST(test_ipv6_dot_family_protocol);
#ifdef DOH_ENABLE
    RUN_TEST(test_ipv6_doh_family_protocol);
#endif
    RUN_TEST(test_ipv4_address_length);
    RUN_TEST(test_ipv4_total_size);
    RUN_TEST(test_ipv6_address_length);
    RUN_TEST(test_ipv6_total_size);
    RUN_TEST(test_ipv4_addresses_and_ports);
    RUN_TEST(test_ipv6_addresses_and_ports);
    RUN_TEST(test_generate_invalid_family);

    std::cout << std::endl
              << "=== parse_proxy_spec ===" << std::endl;
    RUN_TEST(test_parse_ipv4_with_ports);
    RUN_TEST(test_parse_ipv4_without_ports);
    RUN_TEST(test_parse_ipv6_with_ports);
    RUN_TEST(test_parse_ipv6_without_ports);
    RUN_TEST(test_parse_auto_detect_ipv4);
    RUN_TEST(test_parse_auto_detect_ipv6);
    RUN_TEST(test_parse_family_mismatch_v6_as_v4);
    RUN_TEST(test_parse_port_65535);
    RUN_TEST(test_parse_port_zero_explicit);
    RUN_TEST(test_parse_asymmetric_ports);
    RUN_TEST(test_parse_roundtrip_ipv4);
    RUN_TEST(test_parse_roundtrip_ipv6);
    RUN_TEST(test_parse_invalid_no_dash);
    RUN_TEST(test_parse_invalid_empty);
    RUN_TEST(test_parse_invalid_address);
    RUN_TEST(test_parse_invalid_too_many_parts);
    RUN_TEST(test_default_proxy_info);

    std::cout << std::endl
              << tests_run << " tests run, "
              << (tests_run - tests_failed) << " passed, "
              << tests_failed << " failed" << std::endl;

    return tests_failed ? 1 : 0;
}
