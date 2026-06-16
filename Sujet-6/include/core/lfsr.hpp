#pragma once
#include <cstdint>
#include <bit>

namespace CryptoCore {
    class LFSR {
    private:
        std::uint64_t m_state;
        std::uint64_t m_poly;
        std::uint64_t m_initial_state;
        unsigned int m_degree;

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

        [[nodiscard]] inline bool next_bit() noexcept {
            // Sortie du bit de poids faible (LSB)
            bool output = static_cast<bool>(m_state & 1ULL);
            
            // Calcul de la parité du produit bit-à-bit entre l'état et le polynôme de rétroaction
            std::uint64_t feedback = static_cast<std::uint64_t>(std::popcount(m_state & m_poly) & 1ULL);
            
            // Décalage du registre et injection du bit de rétroaction sur le MSB du degré spécifié
            m_state = (m_state >> 1ULL) | (feedback << (m_degree - 1ULL));
            
            return output;
        }

        inline std::uint32_t next_u32() noexcept {
            std::uint32_t result = 0;
            for (unsigned int i = 0; i < 32; ++i) {
                if (next_bit()) {
                    result |= (1U << i);
                }
            }
            return result;
        }

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
}