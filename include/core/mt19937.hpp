#pragma once

#include <array>
#include <cstdint>
#include <span>

/**
 * @file mt19937.hpp
 * @brief Implémentation standard du générateur Mersenne Twister MT19937.
 *
 * État interne : tableau de 624 entiers 32 bits + index courant.
 * Chaque next_u32() applique une transformation de tempering (masquage) sur
 * l'état brut, rendant la sortie statistiquement meilleure mais toujours
 * inversible algébriquement (voir Untemperer).
 */
namespace CryptoCore {

    class MT19937 {
    private:
        static constexpr std::size_t N = 624;                    ///< Taille du registre d'état.
        static constexpr std::size_t M = 397;                    ///< Décalage pour la récurrence.
        static constexpr std::uint32_t MATRIX_A = 0x9908B0DFU;   ///< Matrice de transformation.
        static constexpr std::uint32_t UPPER_MASK = 0x80000000U;  ///< Masque bits hauts.
        static constexpr std::uint32_t LOWER_MASK = 0x7FFFFFFFU;  ///< Masque bits bas.

        std::array<std::uint32_t, N> m_state;  ///< Registre d'état interne.
        std::size_t m_index;                   ///< Position courante dans le registre.

        /// Régénère les 624 mots d'état via la récurrence du twist.
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
        /// Initialise le registre à partir d'une graine unique (algorithme de Matsumoto-Nishimura).
        explicit MT19937(std::uint32_t seed) noexcept : m_index(N) {
            m_state[0] = seed;
            for (std::size_t i = 1; i < N; ++i) {
                m_state[i] = (1812433253U * (m_state[i - 1] ^ (m_state[i - 1] >> 30U)) + i);
            }
        }

        MT19937() noexcept : MT19937(5489U) {}

        /// Injecte un état interne reconstruit (après attaque par untempering).
        void set_state(std::span<const std::uint32_t, N> new_state) noexcept {
            for (std::size_t i = 0; i < N; ++i) {
                m_state[i] = new_state[i];
            }
            m_index = N; // Force le twist au prochain appel de next_u32().
        }

        /// Extrait une valeur 32 bits temperée (sortie observable par l'attaquant).
        [[nodiscard]] std::uint32_t next_u32() noexcept {
            if (m_index >= N) {
                twist();
            }

            std::uint32_t y = m_state[m_index++];

            // Tempering en 4 étapes (chaque étape est une bijection linéaire inversible).
            y ^= (y >> 11U);
            y ^= Restitue_Bit_Left(y, 7U, 0x9D2C5680U);
            y ^= Restitue_Bit_Left(y, 15U, 0xEFC60000U);
            y ^= (y >> 18U);

            return y;
        }

        [[nodiscard]] bool next_bit() noexcept {
            return static_cast<bool>(next_u32() & 1U);
        }

        void reset() noexcept {
            m_index = N;
        }

    private:
        /// Applique un décalage gauche masqué (étape 2 et 3 du tempering).
        static inline std::uint32_t Restitue_Bit_Left(std::uint32_t y, std::uint32_t shift, std::uint32_t mask) noexcept {
            return (y << shift) & mask;
        }
    };

} // namespace CryptoCore
