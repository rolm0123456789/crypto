#pragma once
#include <cstdint>
#include <array>
#include <span>

namespace CryptoAnalysis {
    class Untemperer {
    private:
        static inline constexpr std::uint32_t invert_shift_right(std::uint32_t y, std::uint32_t shift) noexcept {
            std::uint32_t x = y;
            for (unsigned int i = 0; i < 32 / shift; ++i) {
                x = y ^ (x >> shift);
            }
            return x;
        }

        static inline constexpr std::uint32_t invert_shift_left(std::uint32_t y, std::uint32_t shift, std::uint32_t mask) noexcept {
            std::uint32_t x = y;
            for (unsigned int i = 0; i < 32 / shift; ++i) {
                x = y ^ ((x << shift) & mask);
            }
            return x;
        }

    public:
        Untemperer() = delete;

        /**
         * @brief Inverse la fonction de tempering de MT19937.
         * @param tempered_value Valeur 32 bits interceptée en sortie du PRNG.
         * @return std::uint32_t L'état interne brut d'origine correspondant.
         */
        [[nodiscard]] static constexpr std::uint32_t untemper(std::uint32_t tempered_value) noexcept {
            std::uint32_t y = tempered_value;

            // Étape 4 inverse : y ^= (y >> 18)
            y = invert_shift_right(y, 18U);

            // Étape 3 inverse : y ^= ((y << 15) & 0xEFC60000)
            y = invert_shift_left(y, 15U, 0xEFC60000U);

            // Étape 2 inverse : y ^= ((y << 7) & 0x9D2C5680)
            y = invert_shift_left(y, 7U, 0x9D2C5680U);

            // Étape 1 inverse : y ^= (y >> 11)
            y = invert_shift_right(y, 11U);

            return y;
        }

        /**
         * @brief Clone l'état complet à partir de 624 sorties.
         * @param outputs Tableau des 624 sorties observées en continu.
         * @param target_state Tableau de destination pour l'état reconstruit.
         */
        static void clone_state(std::span<const std::uint32_t, 624> outputs, std::span<std::uint32_t, 624> target_state) noexcept {
            for (std::size_t i = 0; i < 624; ++i) {
                target_state[i] = untemper(outputs[i]);
            }
        }
    };
}