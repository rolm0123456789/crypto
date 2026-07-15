#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

/**
 * @file socket_raii.hpp
 * @brief Abstraction RAII des sockets TCP POSIX (move-only).
 *
 * Garantit la fermeture automatique du descripteur de fichier à la destruction,
 * évitant les fuites de ressources dans les boucles serveur de la Partie 3.
 */
namespace CryptoNetwork {

    class SocketRAII {
    private:
        int m_fd;
        static constexpr int INVALID_FD = -1;

    public:
        explicit SocketRAII(int fd = INVALID_FD) noexcept;
        ~SocketRAII() noexcept;

        SocketRAII(const SocketRAII&) = delete;
        SocketRAII& operator=(const SocketRAII&) = delete;
        SocketRAII(SocketRAII&& other) noexcept;
        SocketRAII& operator=(SocketRAII&& other) noexcept;

        [[nodiscard]] static std::optional<SocketRAII> create_tcp_socket() noexcept;
        [[nodiscard]] bool bind_to(std::uint16_t port) noexcept;
        [[nodiscard]] bool listen_on(int backlog = 10) noexcept;
        [[nodiscard]] std::optional<SocketRAII> accept_connection() noexcept;
        [[nodiscard]] bool connect_to(const std::string& address, std::uint16_t port) noexcept;

        /// Envoie intégralement le buffer (gère les envois partiels de send()).
        [[nodiscard]] bool send_all(std::span<const std::uint8_t> data) noexcept;

        /// Reçoit exactement buffer.size() octets (bloquant jusqu'à complétion).
        [[nodiscard]] bool recv_exact(std::span<std::uint8_t> out_buffer) noexcept;

        void close_fd() noexcept;
        [[nodiscard]] bool is_valid() const noexcept { return m_fd != INVALID_FD; }
        [[nodiscard]] int native_handle() const noexcept { return m_fd; }
    };

} // namespace CryptoNetwork
