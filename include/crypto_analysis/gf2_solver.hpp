#pragma once

#include <cstdint>
#include <optional>
#include <span>

/**
 * @file gf2_solver.hpp
 * @brief Solveur de systèmes linéaires sur le corps fini GF(2).
 *
 * Utilisé pour l'attaque LFSR : à partir de 2n bits observés, on construit
 * un système A·c = b où c est le vecteur des coefficients du polynôme de
 * rétroaction, puis on le résout par élimination de Gauss-Jordan.
 * L'addition dans GF(2) correspond à l'opérateur XOR (^).
 */
namespace CryptoAnalysis {

    class GF2Solver {
    public:
        GF2Solver() = delete;
        ~GF2Solver() = delete;
        GF2Solver(const GF2Solver&) = delete;
        GF2Solver& operator=(const GF2Solver&) = delete;

        /**
         * @brief Résout A·x = b sur GF(2) par élimination de Gauss-Jordan.
         * @param augmented_rows  n lignes de la forme [A | b], bit-packed dans uint64_t.
         * @param n               Nombre de variables (n ≤ 63).
         * @return Vecteur solution x compacté en bits, ou nullopt si singulier.
         */
        [[nodiscard]] static std::optional<std::uint64_t> solve(std::span<std::uint64_t> augmented_rows, unsigned int n) noexcept;

        /**
         * @brief Reconstruit le polynôme de rétroaction d'un LFSR de degré n.
         * @param observed_bits  Au moins 2n bits consécutifs de la sortie du LFSR.
         * @param n              Degré du registre.
         * @return Polynôme secret (bits = coefficients c_i), ou nullopt.
         */
        [[nodiscard]] static std::optional<std::uint64_t> recover_polynomial(std::span<const std::uint8_t> observed_bits, unsigned int n) noexcept;
    };

} // namespace CryptoAnalysis
