#include <iostream>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>
#include "network/socket_raii.hpp"
#include "core/mt19937.hpp"

constexpr std::uint16_t PORT = 8080;

void handle_client(CryptoNetwork::SocketRAII client_socket, CryptoCore::MT19937& server_prng, std::vector<std::uint32_t>& active_tokens) noexcept {
    std::uint8_t opcode = 0;
    
    while (true) {
        std::span<std::uint8_t> opcode_span(&opcode, 1);
        if (!client_socket.recv_exact(opcode_span)) {
            break; // Déconnexion propre du client
        }

        if (opcode == 0x01) {
            // Génération d'un nouveau token de session
            std::uint32_t new_token = server_prng.next_u32();
            active_tokens.push_back(new_token);

            std::array<std::uint8_t, 4> packet{};
            std::memcpy(packet.data(), &new_token, sizeof(new_token));
            
            if (!client_socket.send_all(packet)) {
                break;
            }
        } 
        else if (opcode == 0x02) {
            // Vérification d'un token fourni par le client
            std::uint32_t client_token = 0;
            std::array<std::uint8_t, 4> token_buffer{};
            
            if (!client_socket.recv_exact(token_buffer)) {
                break;
            }
            std::memcpy(&client_token, token_buffer.data(), sizeof(client_token));

            // Recherche linéaire optimisée dans le cache des tokens actifs
            auto it = std::find(active_tokens.begin(), active_tokens.end(), client_token);
            std::uint8_t response_status = (it != active_tokens.end()) ? 0x01U : 0x00U;

            std::span<const std::uint8_t> resp_span(&response_status, 1);
            if (!client_socket.send_all(resp_span)) {
                break;
            }
        } 
        else {
            break; // Opcode inconnu : coupure de sécurité
        }
    }
}

int main() {
    // Initialisation du PRNG déterministe (graine fixe pour la reproductibilité du PoC)
    constexpr std::uint32_t INITIAL_SEED = 0xabcdef64U;
    CryptoCore::MT19937 server_prng(INITIAL_SEED);
    
    // Cache des tokens émis (simulation d'une table de session en mémoire)
    std::vector<std::uint32_t> active_sessions;
    active_sessions.reserve(1024);

    auto server_socket_opt = CryptoNetwork::SocketRAII::create_tcp_socket();
    if (!server_socket_opt.has_value()) {
        std::cerr << "[-] Erreur : Impossible d'instancier le socket TCP.\n";
        return EXIT_FAILURE;
    }

    CryptoNetwork::SocketRAII server_socket = std::move(server_socket_opt.value());

    if (!server_socket.bind_to(PORT)) {
        std::cerr << "[-] Erreur : Échec du bind sur le port " << PORT << "\n";
        return EXIT_FAILURE;
    }

    if (!server_socket.listen_on(10)) {
        std::cerr << "[-] Erreur : Échec du listen.\n";
        return EXIT_FAILURE;
    }

    std::cout << "[+] Serveur de Session actif sur le port : " << PORT << "\n";
    std::cout << "[*] En attente de requêtes clients...\n";

    while (true) {
        auto client_socket_opt = server_socket.accept_connection();
        if (client_socket_opt.has_value()) {
            // Traitement synchrone : optimal ici car l'attaquant et la victime opèrent en séquence immédiate
            handle_client(std::move(client_socket_opt.value()), server_prng, active_sessions);
        }
    }

    return EXIT_SUCCESS;
}