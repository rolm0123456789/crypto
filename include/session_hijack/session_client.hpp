#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <optional>
#include <span>
#include <vector>

#include "network/socket_raii.hpp"
#include "session_hijack/protocol.hpp"

/**
 * @file session_client.hpp
 * @brief Fonctions utilitaires partagées par les clients victime et attaquant.
 */
namespace SessionClient {

    /// Établit une connexion TCP vers le serveur local de session.
    [[nodiscard]] inline std::optional<CryptoNetwork::SocketRAII> connect_to_server() noexcept {
        auto socket_opt = CryptoNetwork::SocketRAII::create_tcp_socket();
        if (!socket_opt.has_value()) {
            return std::nullopt;
        }
        CryptoNetwork::SocketRAII socket = std::move(socket_opt.value());
        if (!socket.connect_to("127.0.0.1", SessionProtocol::PORT)) {
            return std::nullopt;
        }
        return socket;
    }

    /// Demande un nouveau token au serveur via l'opcode OP_REQUEST_TOKEN.
    [[nodiscard]] inline bool request_token(CryptoNetwork::SocketRAII& socket, std::uint32_t& out_token) noexcept {
        const std::uint8_t opcode = SessionProtocol::OP_REQUEST_TOKEN;
        if (!socket.send_all(std::span<const std::uint8_t>(&opcode, 1))) {
            return false;
        }

        std::array<std::uint8_t, 4> token_bytes{};
        if (!socket.recv_exact(token_bytes)) {
            return false;
        }

        std::memcpy(&out_token, token_bytes.data(), sizeof(out_token));
        return true;
    }

    /// Soumet un token pour authentification via l'opcode OP_VERIFY_TOKEN.
    [[nodiscard]] inline bool verify_token(CryptoNetwork::SocketRAII& socket, std::uint32_t token, bool& accepted) noexcept {
        std::array<std::uint8_t, 5> packet{};
        packet[0] = SessionProtocol::OP_VERIFY_TOKEN;
        std::memcpy(packet.data() + 1, &token, sizeof(token));

        if (!socket.send_all(packet)) {
            return false;
        }

        std::uint8_t status = 0;
        if (!socket.recv_exact(std::span<std::uint8_t>(&status, 1))) {
            return false;
        }

        accepted = (status == 0x01U);
        return true;
    }

    /// Sérialise un tableau de tokens sur disque (simulation de l'interception réseau).
    [[nodiscard]] inline bool save_tokens(const std::vector<std::uint32_t>& tokens, const char* path) noexcept {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            return false;
        }
        out.write(reinterpret_cast<const char*>(tokens.data()),
                  static_cast<std::streamsize>(tokens.size() * sizeof(std::uint32_t)));
        return static_cast<bool>(out);
    }

    /// Charge des tokens interceptés depuis le fichier de capture réseau simulé.
    [[nodiscard]] inline bool load_tokens(const char* path, std::vector<std::uint32_t>& tokens) noexcept {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in) {
            return false;
        }

        const auto file_size = in.tellg();
        if (file_size <= 0 || (file_size % static_cast<std::streamoff>(sizeof(std::uint32_t))) != 0) {
            return false;
        }

        const std::size_t count = static_cast<std::size_t>(file_size) / sizeof(std::uint32_t);
        tokens.resize(count);
        in.seekg(0, std::ios::beg);
        in.read(reinterpret_cast<char*>(tokens.data()),
                static_cast<std::streamsize>(count * sizeof(std::uint32_t)));
        return static_cast<bool>(in);
    }

} // namespace SessionClient
