#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <vector>

#include "core/mt19937.hpp"
#include "network/socket_raii.hpp"
#include "session_hijack/protocol.hpp"

/**
 * @file server.cpp
 * @brief Serveur de génération de tokens de session vulnérable (Partie 3).
 *
 * Vulnérabilité exploitée : le serveur utilise un MT19937 global non conditionné
 * pour produire les tokens. Tous les clients partagent le même flux PRNG, ce qui
 * permet à un attaquant de reconstruire l'état interne à partir de tokens observés
 * chez d'autres utilisateurs, puis de prédire et usurper leurs sessions futures.
 */

namespace {

    /**
     * Traite les requêtes d'un client connecté jusqu'à déconnexion.
     * @param client_socket  Socket TCP du client (victime ou attaquant).
     * @param server_prng    Générateur global partagé par tous les clients.
     * @param active_tokens  Table des tokens actuellement valides en mémoire.
     */
    void handle_client(CryptoNetwork::SocketRAII client_socket,
                       CryptoCore::MT19937& server_prng,
                       std::vector<std::uint32_t>& active_tokens) noexcept {
        std::uint8_t opcode = 0;

        while (true) {
            std::span<std::uint8_t> opcode_span(&opcode, 1);
            if (!client_socket.recv_exact(opcode_span)) {
                break; // Déconnexion propre du client
            }

            if (opcode == SessionProtocol::OP_REQUEST_TOKEN) {
                // Chaque demande consomme une sortie du PRNG global (faille centrale).
                const std::uint32_t new_token = server_prng.next_u32();
                active_tokens.push_back(new_token);

                std::array<std::uint8_t, 4> packet{};
                std::memcpy(packet.data(), &new_token, sizeof(new_token));

                if (!client_socket.send_all(packet)) {
                    break;
                }
            }
            else if (opcode == SessionProtocol::OP_VERIFY_TOKEN) {
                std::uint32_t client_token = 0;
                std::array<std::uint8_t, 4> token_buffer{};

                if (!client_socket.recv_exact(token_buffer)) {
                    break;
                }
                std::memcpy(&client_token, token_buffer.data(), sizeof(client_token));

                // Vérifie que le token a bien été émis par ce serveur (aucune liaison utilisateur).
                const auto it = std::find(active_tokens.begin(), active_tokens.end(), client_token);
                const bool token_valid = (it != active_tokens.end());
                const std::uint8_t response_status = token_valid ? 0x01U : 0x00U;

                // Token à usage unique : une fois consommé, il ne peut plus authentifier personne.
                if (token_valid) {
                    active_tokens.erase(it);
                }

                const std::span<const std::uint8_t> resp_span(&response_status, 1);
                if (!client_socket.send_all(resp_span)) {
                    break;
                }
            }
            else {
                break; // Opcode inconnu : coupure de sécurité
            }
        }
    }

} // namespace

int main() {
    // Graine fixe pour garantir la reproductibilité de la démonstration en TP.
    constexpr std::uint32_t INITIAL_SEED = 0xabcdef64U;
    CryptoCore::MT19937 server_prng(INITIAL_SEED);

    // Cache en mémoire des tokens émis (aucune expiration ni liaison utilisateur).
    std::vector<std::uint32_t> active_sessions;
    active_sessions.reserve(1024);

    auto server_socket_opt = CryptoNetwork::SocketRAII::create_tcp_socket();
    if (!server_socket_opt.has_value()) {
        std::cerr << "[-] Erreur : Impossible d'instancier le socket TCP.\n";
        return EXIT_FAILURE;
    }

    CryptoNetwork::SocketRAII server_socket = std::move(server_socket_opt.value());

    if (!server_socket.bind_to(SessionProtocol::PORT)) {
        std::cerr << "[-] Erreur : Échec du bind sur le port " << SessionProtocol::PORT << "\n";
        return EXIT_FAILURE;
    }

    if (!server_socket.listen_on(10)) {
        std::cerr << "[-] Erreur : Échec du listen.\n";
        return EXIT_FAILURE;
    }

    std::cout << "[+] Serveur de Session actif sur le port : " << SessionProtocol::PORT << "\n";
    std::cout << "[*] En attente de requêtes clients (Alice, Bob)...\n";

    while (true) {
        auto client_socket_opt = server_socket.accept_connection();
        if (client_socket_opt.has_value()) {
            handle_client(std::move(client_socket_opt.value()), server_prng, active_sessions);
        }
    }

    return EXIT_SUCCESS;
}
