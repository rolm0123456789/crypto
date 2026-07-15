#pragma once

#include <bit>
#include <cstdint>

/**
 * @file lfsr.hpp
 * @brief Implémentation d'un LFSR (Linear Feedback Shift Register) sur GF(2).
 *
 * Architecture Galois à décalage droit :
 *   - Le bit de sortie est le LSB de l'état courant.
 *   - Le bit de rétroaction est la parité (XOR) de (état & polynôme).
 *   - L'état est décalé vers la droite, le bit de rétroaction entre au MSB.
 *
 * Les n premières sorties correspondent aux n bits de l'état initial, ce qui
 * permet leur récupération directe après reconstruction du polynôme secret.
 */
namespace CryptoCore {

    class LFSR {
    private:
        std::uint64_t m_state;          ///< Registre courant (tronqué au degré n).
        std::uint64_t m_poly;           ///< Polynôme de rétroaction (taps actifs = bits à 1).
        std::uint64_t m_initial_state;  ///< Copie de l'état de départ pour reset().
        unsigned int m_degree;          ///< Degré n du registre (ex. 32).

    public:
        constexpr LFSR(std::uint64_t seed, std::uint64_t polynomial, unsigned int degree) noexcept
            : m_state(seed & ((1ULL << degree) - 1)),
              m_poly(polynomial & ((1ULL << degree) - 1)),
              m_initial_state(m_state),
              m_degree(degree) {}

        ~LFSR() = default;
        LFSR(const LFSR&) = default;
        LFSR& operator=(const LFSR&) = default;
        LFSR(LFSR&&) noexcept = default;
        LFSR& operator=(LFSR&&) noexcept = default;

        /// Génère le prochain bit de sortie et met à jour l'état interne.
        [[nodiscard]] inline bool next_bit() noexcept {
            // Sortie du bit de poids faible (LSB) avant décalage.
            bool output = static_cast<bool>(m_state & 1ULL);

            // Rétroaction = parité du produit bit-à-bit (état AND polynôme) sur GF(2).
            std::uint64_t feedback = static_cast<std::uint64_t>(std::popcount(m_state & m_poly) & 1ULL);

            // Décalage droit avec injection du bit de rétroaction au MSB.
            m_state = (m_state >> 1ULL) | (feedback << (m_degree - 1ULL));

            return output;
        }

        /// Agrège 32 bits consécutifs en un entier 32 bits (LSB en premier).
        inline std::uint32_t next_u32() noexcept {
            std::uint32_t result = 0;
            for (unsigned int i = 0; i < 32; ++i) {
                if (next_bit()) {
                    result |= (1U << i);
                }
            }
            return result;
        }

        /// Restaure l'état initial (graine).
        constexpr void reset() noexcept {
            m_state = m_initial_state;
        }

        [[nodiscard]] constexpr std::uint64_t current_state() const noexcept {
            return m_state;
        }

        [[nodiscard]] constexpr unsigned int degree() const noexcept {
            return m_degree;
        }
    };

} // namespace CryptoCore
