#include <iostream>
#include <vector>
#include <array>
#include <iomanip>
#include "core/lfsr.hpp"
#include "crypto_analysis/gf2_solver.hpp"

int main() {
    constexpr unsigned int DEGREE = 32;
    constexpr std::uint64_t SECRET_POLY = 0x80200003ULL; 
    constexpr std::uint64_t SECRET_SEED = 0x1337C0DEULL;

    CryptoCore::LFSR target_lfsr(SECRET_SEED, SECRET_POLY, DEGREE);

    std::cout << "[+] Initialisation du LFSR cible (Secret informatique)\n";
    std::cout << "    - Degré          : " << DEGREE << "\n";
    std::cout << "    - Polynôme Réel  : 0x" << std::hex << std::uppercase << SECRET_POLY << "\n";
    std::cout << "    - État Initial   : 0x" << SECRET_SEED << "\n\n";

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

    std::uint64_t recovered_poly = recovered_poly_opt.value();
    std::cout << "[+] Polynôme reconstruit avec succès : 0x" << std::hex << recovered_poly << "\n";

    if (recovered_poly != SECRET_POLY) {
        std::cerr << "[-] Erreur : Le polynôme trouvé ne correspond pas à la cible.\n";
        return EXIT_FAILURE;
    }

    // Les n premiers bits de sortie correspondent à l'état initial du registre (y_i = S_0[i])
    std::uint64_t recovered_initial_state = 0;
    for (unsigned int i = 0; i < DEGREE; ++i) {
        if (intercepted_bits[i]) {
            recovered_initial_state |= (1ULL << i);
        }
    }

    std::cout << "[+] État initial reconstruit : 0x" << std::hex << recovered_initial_state << "\n";

    CryptoCore::LFSR clone_lfsr(recovered_initial_state, recovered_poly, DEGREE);
    for (std::size_t i = 0; i < INTERCEPTION_SIZE; ++i) {
        (void)clone_lfsr.next_bit();
    }

    std::cout << "[+] État synchronisé après 2n cycles : 0x" << clone_lfsr.current_state() << "\n\n";

    std::cout << "[*] Comparaison et prédiction sur les 100 prochains bits :\n";
    std::cout << "--------------------------------------------------------\n";
    std::cout << "OFFSET | SOURCE CIBLE | CLONE PRÉDIT | STATUS\n";
    std::cout << "--------------------------------------------------------\n";

    bool attack_successful = true;
    for (unsigned int i = 0; i < 100; ++i) {
        bool target_bit = target_lfsr.next_bit();
        bool clone_bit = clone_lfsr.next_bit();

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
    } else {
        std::cerr << "\n[-] ÉCHEC : Divergence dans le flux de prédiction.\n";
        return EXIT_FAILURE;
    }
}