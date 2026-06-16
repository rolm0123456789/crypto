#include "crypto_analysis/gf2_solver.hpp"
#include <utility>

namespace CryptoAnalysis {

    std::optional<std::uint64_t> GF2Solver::solve(std::span<std::uint64_t> augmented_rows, unsigned int n) noexcept {
        if (n > 63 || augmented_rows.size() < n) {
            return std::nullopt;
        }

        for (unsigned int i = 0; i < n; ++i) {
            // Recherche du pivot (première ligne avec le bit i à 1 à partir de la ligne i)
            unsigned int pivot = i;
            while (pivot < n && !(augmented_rows[pivot] & (1ULL << i))) {
                pivot++;
            }

            // Si aucun pivot n'est trouvé, la matrice est singulière (pas de solution unique)
            if (pivot == n) {
                return std::nullopt;
            }

            // Échange de la ligne courante avec la ligne pivot si nécessaire
            if (pivot != i) {
                std::swap(augmented_rows[i], augmented_rows[pivot]);
            }

            // Élimination des coefficients dans toutes les autres lignes
            for (unsigned int j = 0; j < n; ++j) {
                if (j != i && (augmented_rows[j] & (1ULL << i))) {
                    augmented_rows[j] ^= augmented_rows[i];
                }
            }
        }

        // Extraction du vecteur solution depuis la colonne b (située au bit n)
        std::uint64_t solution = 0;
        for (unsigned int i = 0; i < n; ++i) {
            std::uint64_t b_bit = (augmented_rows[i] >> n) & 1ULL;
            solution |= (b_bit << i);
        }

        return solution;
    }

    std::optional<std::uint64_t> GF2Solver::recover_polynomial(std::span<const std::uint8_t> observed_bits, unsigned int n) noexcept {
        if (observed_bits.size() < 2 * n) {
            return std::nullopt;
        }

        std::uint64_t matrix[64] = {0};
        std::span<std::uint64_t> augmented_matrix(matrix, n);

        // Construction du système d'équations
        for (unsigned int i = 0; i < n; ++i) {
            std::uint64_t row = 0;
            for (unsigned int j = 0; j < n; ++j) {
                if (observed_bits[i + j]) {
                    row |= (1ULL << j);
                }
            }
            if (observed_bits[i + n]) {
                row |= (1ULL << n);
            }
            augmented_matrix[i] = row;
        }

        return solve(augmented_matrix, n);
    }
}