/**
 * @file lfsr_poc_app.cpp
 * @brief PoC Partie 1 : attaque algébrique sur un LFSR de degré 32.
 *
 * Déroulement :
 *   1. Instanciation d'un LFSR cible avec polynôme et graine secrets.
 *   2. Interception simulée de 2n = 64 bits consécutifs.
 *   3. Résolution du système linéaire sur GF(2) pour retrouver le polynôme.
 *   4. Reconstruction de l'état initial et synchronisation d'un clone.
 *   5. Vérification de la prédiction sur les 100 bits suivants.
 */

#include <array>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <vector>

#include "core/lfsr.hpp"
#include "crypto_analysis/gf2_solver.hpp"

int main() {
    // Paramètres secrets du LFSR cible (inconnus de l'attaquant en situation réelle).
    constexpr unsigned int DEGREE = 32;
    constexpr std::uint64_t SECRET_POLY = 0x80200003ULL;  // Polynôme primitif de degré 32 (CRC-32).
    constexpr std::uint64_t SECRET_SEED = 0x1337C0DEULL;

    CryptoCore::LFSR target_lfsr(SECRET_SEED, SECRET_POLY, DEGREE);

    std::cout << "[+] Initialisation du LFSR cible (Secret informatique)\n";
    std::cout << "    - Degré          : " << DEGREE << "\n";
    std::cout << "    - Polynôme Réel  : 0x" << std::hex << std::uppercase << SECRET_POLY << "\n";
    std::cout << "    - État Initial   : 0x" << SECRET_SEED << "\n\n";

    // L'attaquant intercepte 2n bits : suffisant pour résoudre le système sur GF(2).
    constexpr std::size_t INTERCEPTION_SIZE = 2 * DEGREE;
    std::vector<std::uint8_t> intercepted_bits;
    intercepted_bits.reserve(INTERCEPTION_SIZE);

    for (std::size_t i = 0; i < INTERCEPTION_SIZE; ++i) {
        intercepted_bits.push_back(static_cast<std::uint8_t>(target_lfsr.next_bit()));
    }

    std::cout << std::dec << "[+] Interception de 2n (" << INTERCEPTION_SIZE << ") bits effectuée.\n";
    std::cout << "[*] Lancement de l'attaque par élimination de Gauss-Jordan sur GF(2)...\n";

    auto recovered_poly_opt = CryptoAnalysis::GF2Solver::recover_polynomial(intercepted_bits, DEGREE);

    if (!recovered_poly_opt.has_value()) {
        std::cerr << "[-] Échec de l'attaque : Matrice singulière ou flux insuffisant.\n";
        return EXIT_FAILURE;
    }

    const std::uint64_t recovered_poly = recovered_poly_opt.value();
    std::cout << "[+] Polynôme reconstruit avec succès : 0x" << std::hex << recovered_poly << "\n";

    if (recovered_poly != SECRET_POLY) {
        std::cerr << "[-] Erreur : Le polynôme trouvé ne correspond pas à la cible.\n";
        return EXIT_FAILURE;
    }

    // Avec un LFSR Galois à décalage droit, les n premières sorties = les n bits de la graine.
    std::uint64_t recovered_initial_state = 0;
    for (unsigned int i = 0; i < DEGREE; ++i) {
        if (intercepted_bits[i]) {
            recovered_initial_state |= (1ULL << i);
        }
    }

    std::cout << "[+] État initial reconstruit : 0x" << std::hex << recovered_initial_state << "\n";

    // Synchronisation du clone : avancer de 2n cycles pour atteindre la position courante.
    CryptoCore::LFSR clone_lfsr(recovered_initial_state, recovered_poly, DEGREE);
    for (std::size_t i = 0; i < INTERCEPTION_SIZE; ++i) {
        (void)clone_lfsr.next_bit();
    }

    std::cout << "[+] État synchronisé après 2n cycles : 0x" << clone_lfsr.current_state() << "\n\n";

    // Validation : prédiction des 100 prochains bits.
    std::cout << "[*] Comparaison et prédiction sur les 100 prochains bits :\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "OFFSET | SOURCE CIBLE | CLONE PRÉDIT | STATUS\n";
    std::cout << "--------------------------------------------------------\n";

    bool attack_successful = true;
    for (unsigned int i = 0; i < 100; ++i) {
        const bool target_bit = target_lfsr.next_bit();
        const bool clone_bit = clone_lfsr.next_bit();

        if (i < 15 || i > 85) {
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
    }

    std::cerr << "\n[-] ÉCHEC : Divergence dans le flux de prédiction.\n";
    return EXIT_FAILURE;
}
