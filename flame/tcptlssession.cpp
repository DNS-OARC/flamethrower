#include <algorithm>
#include <cstring>
#include <iostream>

#include "tcptlssession.h"

static ssize_t gnutls_pull_trampoline(gnutls_transport_ptr_t h, void *buf, size_t len)
{
    auto session = static_cast<TCPTLSSession*>(h);
    return session->gnutls_pull(buf, len);
}

static ssize_t gnutls_push_trampoline(gnutls_transport_ptr_t h, const void *buf, size_t len)
{
    auto session = static_cast<TCPTLSSession*>(h);
    return session->gnutls_push(buf, len);
}

TCPTLSSession::TCPTLSSession(std::shared_ptr<uvw::TCPHandle> handle,
                             TCPSession::malformed_data_cb malformed_data_handler,
                             TCPSession::got_dns_msg_cb got_dns_msg_handler,
                             TCPSession::connection_ready_cb connection_ready_handler,
                             handshake_error_cb handshake_error_handler)
    : TCPSession(handle, malformed_data_handler, got_dns_msg_handler, connection_ready_handler),
      _tls_state{LinkState::HANDSHAKE}, _handshake_error{handshake_error_handler}
{
}

TCPTLSSession::~TCPTLSSession()
{
    gnutls_certificate_free_credentials(_gnutls_cert_credentials);
    gnutls_deinit(_gnutls_session);
}

bool TCPTLSSession::setup()
{
    int ret;

    ret = gnutls_init(&_gnutls_session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "GNUTLS init failed: " << gnutls_strerror(ret) << std::endl;
        return false;
    }

    ret = gnutls_set_default_priority(_gnutls_session);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "GNUTLS failed to set default priority: " << gnutls_strerror(ret) << std::endl;
        return false;
    }

    ret = gnutls_certificate_allocate_credentials(&_gnutls_cert_credentials);
    if (ret < 0) {
        std::cerr << "GNUTLS failed to allocate credentials: " << gnutls_strerror(ret) << std::endl;
        return false;
    }

    ret = gnutls_certificate_set_x509_system_trust(_gnutls_cert_credentials);
    if (ret < 0) {
        std::cerr << "GNUTLS failed to set system trust: " << gnutls_strerror(ret) << std::endl;
        return false;
    }

    ret = gnutls_credentials_set(_gnutls_session, GNUTLS_CRD_CERTIFICATE,
                                 _gnutls_cert_credentials);
    if (ret < 0) {
        std::cerr << "GNUTLS failed to set system credentials" << gnutls_strerror(ret) << std::endl;
        return false;
    }

    gnutls_transport_set_ptr(_gnutls_session, this);
    gnutls_transport_set_pull_function(_gnutls_session, gnutls_pull_trampoline);
    gnutls_transport_set_push_function(_gnutls_session, gnutls_push_trampoline);
    gnutls_handshake_set_timeout(_gnutls_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    return true;
}

void TCPTLSSession::on_connect_event()
{
    do_handshake();
}

// gracefully terminate the session
void TCPTLSSession::close()
{
    _tls_state = LinkState::CLOSE;
    gnutls_bye(_gnutls_session, GNUTLS_SHUT_WR);
    TCPSession::close();
}

void TCPTLSSession::receive_data(const char data[], size_t len)
{
    _pull_buffer.append(data, len);
    switch(_tls_state) {
    case LinkState::HANDSHAKE:
        do_handshake();
        break;

    case LinkState::DATA:
        for (;;) {
            char buf[16384];
            ssize_t len = gnutls_record_recv(_gnutls_session, buf, sizeof(buf));
            if (len > 0) {
                TCPSession::receive_data(buf, len);
            } else {
                if (len == GNUTLS_E_AGAIN) {
                    // Check if we don't have any data left to read
                    if (_pull_buffer.empty()) {
                        break;
                    }
                    continue;
                } else if (len == GNUTLS_E_INTERRUPTED) {
                    continue;
                }
                break;
            }
        }
        break;

    case LinkState::CLOSE:
        break;
    }
}

void TCPTLSSession::write(std::unique_ptr<char[]> data, size_t len)
{
    ssize_t sent = gnutls_record_send(_gnutls_session, data.get(), len);
    if (sent < 0) {
        std::cerr << "Error in sending data: " << gnutls_strerror(sent) << std::endl;
    }
}

void TCPTLSSession::do_handshake()
{
    int err = gnutls_handshake(_gnutls_session);
    if (err == GNUTLS_E_SUCCESS) {
        _tls_state = LinkState::DATA;
        TCPSession::on_connect_event();
    } else if (err < 0 && gnutls_error_is_fatal(err)) {
        std::cerr << "Handshake failed: " << gnutls_strerror(err) << std::endl;
        _handshake_error();
    } else if (err != GNUTLS_E_AGAIN && err != GNUTLS_E_INTERRUPTED) {
        std::cout << "Handshake " << gnutls_strerror(err) << std::endl;
    }
}

int TCPTLSSession::gnutls_pull(void *buf, size_t len)
{
    if (!_pull_buffer.empty()) {
        len = std::min(len, _pull_buffer.size());
        std::memcpy(buf, _pull_buffer.data(), len);
        _pull_buffer.erase(0, len);
        return len;
    }

    errno = EAGAIN;
    return -1;
}

int TCPTLSSession::gnutls_push(const void *buf, size_t len)
{
    auto data = std::make_unique<char[]>(len);
    memcpy(data.get(), const_cast<char *>(reinterpret_cast<const char *>(buf)), len);
    TCPSession::write(std::move(data), len);
    return len;
}
