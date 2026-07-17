/**
 * @file mt19937_poc_app.cpp
 * @brief PoC Partie 2 : clonage complet de l'état interne du MT19937.
 *
 * Déroulement :
 *   1. Instanciation d'un MT19937 cible (simule un serveur vulnérable).
 *   2. Interception simulée de 624 sorties 32 bits consécutives.
 *   3. Inversion du tempering (untemper) pour restaurer l'état brut.
 *   4. Instanciation d'un clone synchronisé sur l'état piraté.
 *   5. Vérification de la prédiction sur les 100 prochaines valeurs.
 */

#include <array>
#include <cstdlib>
#include <iomanip>
#include <iostream>

#include "core/mt19937.hpp"
#include "crypto_analysis/untemperer.hpp"

int main() {
    constexpr std::uint32_t TARGET_SEED = 0xDEADC0DEU;
    CryptoCore::MT19937 target_generator(TARGET_SEED);

    std::cout << "[+] Initialisation du Mersenne Twister cible (Serveur)\n";
    std::cout << "    - Graine utilisée : 0x" << std::hex << std::uppercase << TARGET_SEED << "\n\n";

    // 624 sorties = taille exacte du registre d'état → clonage complet possible.
    constexpr std::size_t REQUIRED_OUTPUTS = 624;
    std::array<std::uint32_t, REQUIRED_OUTPUTS> intercepted_outputs{};

    for (std::size_t i = 0; i < REQUIRED_OUTPUTS; ++i) {
        intercepted_outputs[i] = target_generator.next_u32();
    }

    std::cout << "[+] Interception de " << std::dec << REQUIRED_OUTPUTS << " sorties consécutives effectuée.\n";
    std::cout << "[*] Analyse et inversion algébrique des masquages binaires...\n";

    std::array<std::uint32_t, REQUIRED_OUTPUTS> reconstructed_state{};
    CryptoAnalysis::Untemperer::clone_state(intercepted_outputs, reconstructed_state);
    std::cout << "[+] Reconstitution de l'état interne exécutée avec succès.\n\n";

    // Le clone partage désormais le même état interne que la cible.
    CryptoCore::MT19937 cloned_generator;
    cloned_generator.set_state(reconstructed_state);

    constexpr unsigned int PREDICTION_COUNT = 100;
    std::cout << "[*] Comparaison et prédiction sur les " << PREDICTION_COUNT << " prochaines valeurs :\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "INDEX  | VALEUR CIBLE | CLONE PRÉDIT | STATUS\n";
    std::cout << "--------------------------------------------------------\n";

    bool attack_successful = true;
    for (unsigned int i = 0; i < PREDICTION_COUNT; ++i) {
        const std::uint32_t target_val = target_generator.next_u32();
        const std::uint32_t clone_val = cloned_generator.next_u32();

        if (i < 10 || i >= 90) {
            std::cout << "  " << std::setw(2) << std::dec << i << "   |   "
                      << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << target_val << "   |   "
                      << std::setw(8) << std::setfill('0') << clone_val << "   | "
                      << (target_val == clone_val ? "MATCH" : "MISMATCH") << "\n";
        } else if (i == 10) {
            std::cout << "  ...  |   ........   |   ........   | ...\n";
        }

        if (target_val != clone_val) {
            attack_successful = false;
        }
    }
    std::cout << "--------------------------------------------------------\n";

    if (attack_successful) {
        std::cout << "\n[+] CLONAGE RÉUSSI : Alignement absolu du générateur cloné sur le serveur.\n";
        return EXIT_SUCCESS;
    }

    std::cerr << "\n[-] ÉCHEC : Les valeurs prédites divergent du flux cible.\n";
    return EXIT_FAILURE;
}
