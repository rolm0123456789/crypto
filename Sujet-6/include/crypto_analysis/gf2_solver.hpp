#pragma once
#include <cstdint>
#include <span>
#include <optional>

namespace CryptoAnalysis {
    class GF2Solver {
    public:
        GF2Solver() = delete;
        ~GF2Solver() = delete;
        GF2Solver(const GF2Solver&) = delete;
        GF2Solver& operator=(const GF2Solver&) = delete;

        /**
         * @brief Résout un système linéaire A * x = b sur GF(2) via l'élimination de Gauss-Jordan.
         * @param augmented_rows Tableau de n lignes contenant [A | b]. Chaque ligne a ses coefficients 
         * de A dans les bits 0 à n-1, et l'élément de b au bit n.
         * @param n Nombre de variables et d'équations (n <= 63).
         * @return std::optional<std::uint64_t> Le vecteur solution x compacté en bits, ou std::nullopt si le système n'a pas de solution unique.
         */
        [[nodiscard]] static std::optional<std::uint64_t> solve(std::span<std::uint64_t> augmented_rows, unsigned int n) noexcept;

        /**
         * @brief Reconstruit le polynôme de rétroaction d'un LFSR à partir de 2n bits observés.
         * @param observed_bits Flux de 2n bits consécutifs extraits du générateur (0 ou 1).
         * @param n Degré du LFSR.
         * @return std::optional<std::uint64_t> Le polynôme détecté ou std::nullopt.
         */
        [[nodiscard]] static std::optional<std::uint64_t> recover_polynomial(std::span<const std::uint8_t> observed_bits, unsigned int n) noexcept;
    };
}