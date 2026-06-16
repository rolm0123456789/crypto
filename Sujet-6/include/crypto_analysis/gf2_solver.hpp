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

        [[nodiscard]] static std::optional<std::uint64_t> solve(std::span<std::uint64_t> augmented_rows, unsigned int n) noexcept;

        /**
         * @brief Reconstruit le polynôme de rétroaction d'un LFSR à partir de 2n bits observés.
         * @param observed_bits Flux d'octets modélisant les bits (0 ou 1) extraits du générateur.
         */
        [[nodiscard]] static std::optional<std::uint64_t> recover_polynomial(std::span<const std::uint8_t> observed_bits, unsigned int n) noexcept;
    };
}