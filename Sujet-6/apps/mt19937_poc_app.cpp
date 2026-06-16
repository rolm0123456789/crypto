#include <iostream>
#include <array>
#include <iomanip>
#include "core/mt19937.hpp"
#include "crypto_analysis/untemperer.hpp"

int main() {
    // Configuration de la graine du serveur cible
    constexpr std::uint32_t TARGET_SEED = 0xDEADC0DEU;
    CryptoCore::MT19937 target_generator(TARGET_SEED);

    std::cout << "[+] Initialisation du Mersenne Twister cible (Serveur)\n";
    std::cout << "    - Graine utilisée : 0x" << std::hex << std::uppercase << TARGET_SEED << "\n\n";

    // Phase 1 : Interception de 624 sorties consécutives de 32 bits
    constexpr std::size_t REQUIRED_OUTPUTS = 624;
    std::array<std::uint32_t, REQUIRED_OUTPUTS> intercepted_outputs{};

    for (std::size_t i = 0; i < REQUIRED_OUTPUTS; ++i) {
        intercepted_outputs[i] = target_generator.next_u32();
    }

    std::cout << "[+] Interception de " << std::dec << REQUIRED_OUTPUTS << " sorties consécutives effectuée.\n";

    // Phase 2 : Extraction de l'état interne par inversion du tempering (Untempering)
    std::cout << "[*] Analyse et inversion algébrique des masquages binaires...\n";
    std::array<std::uint32_t, REQUIRED_OUTPUTS> reconstructed_state{};
    
    CryptoAnalysis::Untemperer::clone_state(intercepted_outputs, reconstructed_state);
    std::cout << "[+] Reconstitution de l'état interne exécutée avec succès.\n\n";

    // Phase 3 : Instanciation du clone avec l'état piraté
    CryptoCore::MT19937 cloned_generator;
    cloned_generator.set_state(reconstructed_state);

    // Phase 4 : Vérification et prédiction des 100 prochaines valeurs du flux
    constexpr unsigned int PREDICTION_COUNT = 100;
    std::cout << "[*] Comparaison et prédiction sur les " << PREDICTION_COUNT << " prochaines valeurs :\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "INDEX  | VALEUR CIBLE | CLONE PRÉDIT | STATUS\n";
    std::cout << "--------------------------------------------------------\n";

    bool attack_successful = true;
    for (unsigned int i = 0; i < PREDICTION_COUNT; ++i) {
        std::uint32_t target_val = target_generator.next_u32();
        std::uint32_t clone_val = cloned_generator.next_u32();

        if (i < 10 || i >= 90) { // Affichage restreint pour préserver la concision de la CLI
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
    } else {
        std::cerr << "\n[-] ÉCHEC : Les valeurs prédites divergent du flux cible.\n";
        return EXIT_FAILURE;
    }
}