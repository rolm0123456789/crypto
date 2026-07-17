#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "session_hijack/protocol.hpp"
#include "session_hijack/session_client.hpp"

/**
 * @file victim.cpp
 * @brief Client « victime » (Alice) du scénario d'usurpation de session.
 *
 * Deux modes :
 *   setup — Simule l'activité normale d'Alice : elle reçoit N tokens du serveur.
 *           Ces tokens sont enregistrés sur disque pour représenter une capture
 *           réseau passive effectuée par l'attaquant.
 *   login — Alice demande un nouveau token de session (le N+1ème du flux global).
 *           L'attaquant, ayant cloné le PRNG, peut prédire cette valeur à l'avance.
 */

namespace {

    void print_usage(const char* program_name) {
        std::cerr << "Usage:\n"
                  << "  " << program_name << " setup [count] [output_file]\n"
                  << "  " << program_name << " login [output_file]\n"
                  << "  " << program_name << " auth [token_file]\n";
    }

    int run_setup(std::size_t count, const char* output_file) {
        auto socket_opt = SessionClient::connect_to_server();
        if (!socket_opt.has_value()) {
            std::cerr << "[-] Victime (Alice) : connexion au serveur impossible.\n";
            return EXIT_FAILURE;
        }

        std::cout << "[Alice] Simulation de l'activité utilisateur : demande de "
                  << count << " tokens de session...\n";

        std::vector<std::uint32_t> tokens;
        tokens.reserve(count);

        for (std::size_t i = 0; i < count; ++i) {
            std::uint32_t token = 0;
            if (!SessionClient::request_token(socket_opt.value(), token)) {
                std::cerr << "[-] Victime (Alice) : erreur réseau à l'index " << i << ".\n";
                return EXIT_FAILURE;
            }
            tokens.push_back(token);
        }

        if (!SessionClient::save_tokens(tokens, output_file)) {
            std::cerr << "[-] Victime (Alice) : impossible d'écrire " << output_file << ".\n";
            return EXIT_FAILURE;
        }

        std::cout << "[Alice] " << count << " tokens enregistrés dans " << output_file
                  << " (simulation d'une capture réseau passive).\n";
        return EXIT_SUCCESS;
    }

    int run_login(const char* output_file) {
        auto socket_opt = SessionClient::connect_to_server();
        if (!socket_opt.has_value()) {
            std::cerr << "[-] Victime (Alice) : connexion au serveur impossible.\n";
            return EXIT_FAILURE;
        }

        std::cout << "[Alice] Demande d'un nouveau token de session au serveur...\n";

        std::uint32_t token = 0;
        if (!SessionClient::request_token(socket_opt.value(), token)) {
            std::cerr << "[-] Victime (Alice) : échec de la demande de token.\n";
            return EXIT_FAILURE;
        }

        std::cout << "[Alice] Token reçu du serveur : 0x" << std::hex << token << std::dec << "\n";

        if (!SessionClient::save_tokens(std::vector<std::uint32_t>{token}, output_file)) {
            std::cerr << "[-] Victime (Alice) : impossible d'écrire " << output_file << ".\n";
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    int run_auth(const char* token_file) {
        std::vector<std::uint32_t> tokens;
        if (!SessionClient::load_tokens(token_file, tokens) || tokens.empty()) {
            std::cerr << "[-] Victime (Alice) : impossible de lire " << token_file << ".\n";
            return EXIT_FAILURE;
        }

        auto socket_opt = SessionClient::connect_to_server();
        if (!socket_opt.has_value()) {
            std::cerr << "[-] Victime (Alice) : connexion au serveur impossible.\n";
            return EXIT_FAILURE;
        }

        const std::uint32_t token = tokens.front();
        std::cout << "[Alice] Tentative d'authentification avec son token 0x"
                  << std::hex << token << std::dec << "...\n";

        bool accepted = false;
        if (!SessionClient::verify_token(socket_opt.value(), token, accepted)) {
            std::cerr << "[-] Victime (Alice) : erreur lors de la vérification du token.\n";
            return EXIT_FAILURE;
        }

        if (accepted) {
            std::cout << "[Alice] Authentification réussie avec son propre token.\n";
            return EXIT_SUCCESS;
        }

        std::cout << "[Alice] Authentification REFUSÉE : le token a déjà été consommé par l'attaquant.\n";
        return EXIT_FAILURE;
    }

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const std::string mode = argv[1];

    if (mode == "setup") {
        std::size_t count = SessionProtocol::VICTIM_OBSERVED_COUNT;
        const char* output_file = SessionProtocol::OBSERVED_TOKENS_FILE;

        if (argc >= 3) {
            count = static_cast<std::size_t>(std::stoul(argv[2]));
        }
        if (argc >= 4) {
            output_file = argv[3];
        }

        return run_setup(count, output_file);
    }

    if (mode == "login") {
        const char* output_file = SessionProtocol::VICTIM_LOGIN_TOKEN_FILE;
        if (argc >= 3) {
            output_file = argv[3];
        }
        return run_login(output_file);
    }

    if (mode == "auth") {
        const char* token_file = SessionProtocol::VICTIM_LOGIN_TOKEN_FILE;
        if (argc >= 3) {
            token_file = argv[3];
        }
        return run_auth(token_file);
    }

    print_usage(argv[0]);
    return EXIT_FAILURE;
}
