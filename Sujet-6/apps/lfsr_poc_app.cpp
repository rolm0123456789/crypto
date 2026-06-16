#include <iostream>
#include <vector>
#include <array>
#include <iomanip>
#include "core/lfsr.hpp"
#include "crypto_analysis/gf2_solver.hpp"

int main() {
    // Configuration du LFSR cible (Sujet d'étude)
    // Degré n = 32. Polynôme primitif standard : x^32 + x^22 + x^2 + x + 1
    constexpr unsigned int DEGREE = 32;
    constexpr std::uint64_t SECRET_POLY = 0x80200003ULL; 
    constexpr std::uint64_t SECRET_SEED = 0x1337C0DEULL;

    CryptoCore::LFSR target_lfsr(SECRET_SEED, SECRET_POLY, DEGREE);

    std::cout << "[+] Initialisation du LFSR cible (Secret informatique)\n";
    std::cout << "    - Degré          : " << DEGREE << "\n";
    std::cout << "    - Polynôme Réel  : 0x" << std::hex << std::uppercase << SECRET_POLY << "\n";
    std::cout << "    - État Initial   : 0x" << SECRET_SEED << "\n\n";

    // Phase 1 : Interception de 2n bits consécutifs du flux de sortie
    constexpr std::size_t INTERCEPTION_SIZE = 2 * DEGREE;
    std::vector<bool> intercepted_bits;
    intercepted_bits.reserve(INTERCEPTION_SIZE);

    for (std::size_t i = 0; i < INTERCEPTION_SIZE; ++i) {
        intercepted_bits.push_back(target_lfsr.next_bit());
    }

    std::cout << "[+] Interception de 2n (" << INTERCEPTION_SIZE << ") bits effectuée.\n";

    // Phase 2 : Cryptanalyse - Reconstruction algébrique via solveur GF(2)
    std::cout << "[*] Lancement de l'attaque par élimination de Gauss-Jordan sur GF(2)...\n";
    auto recovered_poly_opt = CryptoAnalysis::GF2Solver::recover_polynomial(intercepted_bits, DEGREE);

    if (!recovered_poly_opt.has_value()) {
        std::cerr << "[-] Échec de l'attaque : Matrice singulière ou flux insuffisant.\n";
        return EXIT_FAILURE;
    }

    std::uint64_t recovered_poly = recovered_poly_opt.value();
    std::cout << "[+] Polynôme reconstruit avec succès : 0x" << std::hex << recovered_poly << "\n";

    // Validation du polynôme
    if (recovered_poly != SECRET_POLY) {
        std::cerr << "[-] Erreur : Le polynôme trouvé ne correspond pas à la cible.\n";
        return EXIT_FAILURE;
    }

    // Phase 3 : Reconstruction de l'état interne actuel
    // Puisque la sortie est le LSB direct du registre glissant, les n derniers bits interceptés
    // forment précisément l'état interne du registre à cet instant t.
    std::uint64_t recovered_state = 0;
    for (unsigned int i = 0; i < DEGREE; ++i) {
        if (intercepted_bits[(INTERCEPTION_SIZE - DEGREE) + i]) {
            recovered_state |= (1ULL << i);
        }
    }

    std::cout << "[+] État interne synchronisé détecté : 0x" << std::hex << recovered_state << "\n\n";

    // Phase 4 : Instanciation du clone et prédiction du futur
    // Le clone utilise le polynôme craqué et l'état extrait
    CryptoCore::LFSR clone_lfsr(recovered_state, recovered_poly, DEGREE);

    std::cout << "[*] Comparaison et prédiction sur les 100 prochains bits :\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "OFFSET | SOURCE CIBLE | CLONE PRÉDIT | STATUS\n";
    std::cout << "--------------------------------------------------------\n";

    bool attack_successful = true;
    for (unsigned int i = 0; i < 100; ++i) {
        bool target_bit = target_lfsr.next_bit();
        bool clone_bit = clone_lfsr.next_bit();

        if (i < 15 || i > 85) { // Affichage tronqué pour la lisibilité de la CLI
            std::cout << "  " << std::setw(4) << std::dec << i << " |      " 
                      << target_bit << "       |       " << clone_bit << "      | " 
                      << (target_bit == clone_bit ? "MATCH" : "MISMATCH") << "\n";
        } else if (i == 15) {
            std::cout << "  ...  |     ...      |      ...     | ...\n";
        }

        if (target_bit != clone_bit) {
            attack_successful = false;
        }
    }
    std::cout << "--------------------------------------------------------\n";

    if (attack_successful) {
        std::cout << "\n[+] CLONAGE RÉUSSI : Prédiction exacte à 100%. Le secret est compromis.\n";
        return EXIT_SUCCESS;
    } else {
        std::cerr << "\n[-] ÉCHEC : Divergence dans le flux de prédiction.\n";
        return EXIT_FAILURE;
    }
}