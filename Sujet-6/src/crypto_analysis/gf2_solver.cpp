#include "crypto_analysis/gf2_solver.hpp"

#include <utility>

namespace CryptoAnalysis {

    std::optional<std::uint64_t> GF2Solver::solve(std::span<std::uint64_t> augmented_rows, unsigned int n) noexcept {
        if (n > 63 || augmented_rows.size() < n) {
            return std::nullopt;
        }

        // Élimination de Gauss-Jordan : chaque colonne i devient pivot.
        for (unsigned int i = 0; i < n; ++i) {
            // Recherche d'une ligne avec un 1 en position i (pivot).
            unsigned int pivot = i;
            while (pivot < n && !(augmented_rows[pivot] & (1ULL << i))) {
                pivot++;
            }

            if (pivot == n) {
                return std::nullopt; // Matrice singulière : pas de solution unique.
            }

            if (pivot != i) {
                std::swap(augmented_rows[i], augmented_rows[pivot]);
            }

            // Annulation des autres 1 de la colonne i (XOR = soustraction dans GF(2)).
            for (unsigned int j = 0; j < n; ++j) {
                if (j != i && (augmented_rows[j] & (1ULL << i))) {
                    augmented_rows[j] ^= augmented_rows[i];
                }
            }
        }

        // Lecture de la solution dans la colonne b (bit n de chaque ligne).
        std::uint64_t solution = 0;
        for (unsigned int i = 0; i < n; ++i) {
            const std::uint64_t b_bit = (augmented_rows[i] >> n) & 1ULL;
            solution |= (b_bit << i);
        }

        return solution;
    }

    std::optional<std::uint64_t> GF2Solver::recover_polynomial(std::span<const std::uint8_t> observed_bits, unsigned int n) noexcept {
        if (observed_bits.size() < 2 * n) {
            return std::nullopt;
        }

        // Construction de la matrice augmentée [A | b] à partir des bits observés.
        // Ligne i : (y_i, y_{i+1}, ..., y_{i+n-1}) · c = y_{i+n}
        std::uint64_t matrix[64] = {0};
        std::span<std::uint64_t> augmented_matrix(matrix, n);

        for (unsigned int i = 0; i < n; ++i) {
            std::uint64_t row = 0;
            for (unsigned int j = 0; j < n; ++j) {
                if (observed_bits[i + j]) {
                    row |= (1ULL << j);
                }
            }
            if (observed_bits[i + n]) {
                row |= (1ULL << n); // Colonne b : bit cible y_{i+n}
            }
            augmented_matrix[i] = row;
        }

        return solve(augmented_matrix, n);
    }

} // namespace CryptoAnalysis
