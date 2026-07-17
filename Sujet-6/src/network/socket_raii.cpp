#include "network/socket_raii.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

#include <utility>

namespace CryptoNetwork {

    SocketRAII::SocketRAII(int fd) noexcept : m_fd(fd) {}

    SocketRAII::~SocketRAII() noexcept {
        close_fd();
    }

    SocketRAII::SocketRAII(SocketRAII&& other) noexcept : m_fd(other.m_fd) {
        other.m_fd = INVALID_FD;
    }

    SocketRAII& SocketRAII::operator=(SocketRAII&& other) noexcept {
        if (this != &other) {
            close_fd();
            m_fd = other.m_fd;
            other.m_fd = INVALID_FD;
        }
        return *this;
    }

    std::optional<SocketRAII> SocketRAII::create_tcp_socket() noexcept {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd == INVALID_FD) {
            return std::nullopt;
        }

        // SO_REUSEADDR : évite l'erreur "Address already in use" après un redémarrage rapide.
        int opt = 1;
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            ::close(fd);
            return std::nullopt;
        }
        return SocketRAII(fd);
    }

    bool SocketRAII::bind_to(std::uint16_t port) noexcept {
        if (!is_valid()) {
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        return ::bind(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    }

    bool SocketRAII::listen_on(int backlog) noexcept {
        if (!is_valid()) {
            return false;
        }
        return ::listen(m_fd, backlog) == 0;
    }

    std::optional<SocketRAII> SocketRAII::accept_connection() noexcept {
        if (!is_valid()) {
            return std::nullopt;
        }

        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = ::accept(m_fd, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);

        if (client_fd == INVALID_FD) {
            return std::nullopt;
        }
        return SocketRAII(client_fd);
    }

    bool SocketRAII::connect_to(const std::string& address, std::uint16_t port) noexcept {
        if (!is_valid()) {
            return false;
        }

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);

        if (::inet_pton(AF_INET, address.c_str(), &server_addr.sin_addr) <= 0) {
            return false;
        }
        return ::connect(m_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == 0;
    }

    bool SocketRAII::send_all(std::span<const std::uint8_t> data) noexcept {
        if (!is_valid()) {
            return false;
        }

        const std::uint8_t* ptr = data.data();
        std::size_t bytes_left = data.size();

        // Boucle nécessaire car send() peut retourner un envoi partiel.
        while (bytes_left > 0) {
            ssize_t bytes_sent = ::send(m_fd, ptr, bytes_left, 0);
            if (bytes_sent < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return false;
            } else if (bytes_sent == 0) {
                return false;
            }
            ptr += bytes_sent;
            bytes_left -= static_cast<std::size_t>(bytes_sent);
        }
        return true;
    }

    bool SocketRAII::recv_exact(std::span<std::uint8_t> out_buffer) noexcept {
        if (!is_valid()) {
            return false;
        }

        std::uint8_t* ptr = out_buffer.data();
        std::size_t bytes_left = out_buffer.size();

        // Boucle nécessaire car recv() peut retourner une réception partielle.
        while (bytes_left > 0) {
            ssize_t bytes_received = ::recv(m_fd, ptr, bytes_left, 0);
            if (bytes_received < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return false;
            } else if (bytes_received == 0) {
                return false;
            }
            ptr += bytes_received;
            bytes_left -= static_cast<std::size_t>(bytes_received);
        }
        return true;
    }

    void SocketRAII::close_fd() noexcept {
        if (m_fd != INVALID_FD) {
            ::close(m_fd);
            m_fd = INVALID_FD;
        }
    }

} // namespace CryptoNetwork
