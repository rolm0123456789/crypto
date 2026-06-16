#pragma once
#include <cstdint>
#include <string>
#include <span>
#include <optional>

namespace CryptoNetwork {
    class SocketRAII {
    private:
        int m_fd;
        static constexpr int INVALID_FD = -1;

    public:
        explicit SocketRAII(int fd = INVALID_FD) noexcept;
        ~SocketRAII() noexcept;

        // Sémantique de déplacement unique (Move-only)
        SocketRAII(const SocketRAII&) = delete;
        SocketRAII& operator=(const SocketRAII&) = delete;
        SocketRAII(SocketRAII&& other) noexcept;
        SocketRAII& operator=(SocketRAII&& other) noexcept;

        // Opérations d'initialisation du cycle de vie
        [[nodiscard]] static std::optional<SocketRAII> create_tcp_socket() noexcept;
        [[nodiscard]] bool bind_to(std::uint16_t port) noexcept;
        [[nodiscard]] bool listen_on(int backlog = 10) noexcept;
        [[nodiscard]] std::optional<SocketRAII> accept_connection() noexcept;
        [[nodiscard]] bool connect_to(const std::string& address, std::uint16_t port) noexcept;

        // Entrées/Sorties synchrones block-packed
        [[nodiscard]] bool send_all(std::span<const std::uint8_t> data) noexcept;
        [[nodiscard]] bool recv_exact(std::span<std::uint8_t> out_buffer) noexcept;

        void close_fd() noexcept;
        [[nodiscard]] bool is_valid() const noexcept { return m_fd != INVALID_FD; }
        [[nodiscard]] int native_handle() const noexcept { return m_fd; }
    };
}