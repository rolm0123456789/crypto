#pragma once
#include <cstdint>
#include <array>
#include <span>

namespace CryptoCore {
    class MT19937 {
    private:
        static constexpr std::size_t N = 624;
        static constexpr std::size_t M = 397;
        static constexpr std::uint32_t MATRIX_A = 0x9908B0DFU;
        static constexpr std::uint32_t UPPER_MASK = 0x80000000U;
        static constexpr std::uint32_t LOWER_MASK = 0x7FFFFFFFU;

        std::array<std::uint32_t, N> m_state;
        std::size_t m_index;

        void twist() noexcept {
            for (std::size_t i = 0; i < N; ++i) {
                std::uint32_t x = (m_state[i] & UPPER_MASK) | (m_state[(i + 1) % N] & LOWER_MASK);
                std::uint32_t x_xor = x >> 1U;
                if (x & 1U) {
                    x_xor ^= MATRIX_A;
                }
                m_state[i] = m_state[(i + M) % N] ^ x_xor;
            }
            m_index = 0;
        }

    public:
        explicit MT19937(std::uint32_t seed) noexcept : m_index(N) {
            m_state[0] = seed;
            for (std::size_t i = 1; i < N; ++i) {
                m_state[i] = (1812433253U * (m_state[i - 1] ^ (m_state[i - 1] >> 30U)) + i);
            }
        }

        MT19937() noexcept : MT19937(5489U) {}

        void set_state(std::span<const std::uint32_t, N> new_state) noexcept {
            for (std::size_t i = 0; i < N; ++i) {
                m_state[i] = new_state[i];
            }
            m_index = N; // Force le twist immédiat au prochain appel de next_u32()
        }

        [[nodiscard]] std::uint32_t next_u32() noexcept {
            if (m_index >= N) {
                twist();
            }

            std::uint32_t y = m_state[m_index++];

            // Fonctions de Masquage (Tempering)
            y ^= (y >> 11U);
            y ^= Restitue_Bit_Left(y, 7U, 0x9D2C5680U);
            y ^= Restitue_Bit_Left(y, 15U, 0xEFC60000U);
            y ^= (y >> 18U);

            return y;
        }

        // Abstraction pour satisfaire le concept PRNG
        [[nodiscard]] bool next_bit() noexcept {
            return static_cast<bool>(next_u32() & 1U);
        }

        void reset() noexcept {
            m_index = N;
        }

    private:
        static inline std::uint32_t Restitue_Bit_Left(std::uint32_t y, std::uint32_t shift, std::uint32_t mask) noexcept {
            return (y << shift) & mask;
        }
    };
}