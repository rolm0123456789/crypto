#pragma once

#include <array>
#include <cstdint>
#include <span>

/**
 * @file untemperer.hpp
 * @brief Inversion de la fonction de tempering du MT19937.
 *
 * Le tempering applique 4 transformations linéaires bijectives sur l'état brut.
 * Chaque étape est inversible indépendamment en exploitant les zéros insérés
 * par les décalages logiques. 624 inversions consécutives restaurent l'état
 * interne complet du générateur.
 */
namespace CryptoAnalysis {

    class Untemperer {
    private:
        /// Inverse y ^= (y >> shift) en réinjectant progressivement les bits connus.
        static inline constexpr std::uint32_t invert_shift_right(std::uint32_t y, std::uint32_t shift) noexcept {
            std::uint32_t x = y;
            for (unsigned int i = 0; i < 32 / shift; ++i) {
                x = y ^ (x >> shift);
            }
            return x;
        }

        /// Inverse y ^= ((y << shift) & mask) en propageant les bits de gauche à droite.
        static inline constexpr std::uint32_t invert_shift_left(std::uint32_t y, std::uint32_t shift, std::uint32_t mask) noexcept {
            std::uint32_t x = y;
            for (unsigned int i = 0; i < 32 / shift; ++i) {
                x = y ^ ((x << shift) & mask);
            }
            return x;
        }

    public:
        Untemperer() = delete;

        /// Inverse les 4 étapes de tempering dans l'ordre inverse (4 → 1).
        [[nodiscard]] static constexpr std::uint32_t untemper(std::uint32_t tempered_value) noexcept {
            std::uint32_t y = tempered_value;

            y = invert_shift_right(y, 18U);                        // Étape 4 inverse
            y = invert_shift_left(y, 15U, 0xEFC60000U);            // Étape 3 inverse
            y = invert_shift_left(y, 7U, 0x9D2C5680U);             // Étape 2 inverse
            y = invert_shift_right(y, 11U);                        // Étape 1 inverse

            return y;
        }

        /// Reconstruit les 624 mots d'état brut à partir de 624 sorties temperées.
        static void clone_state(std::span<const std::uint32_t, 624> outputs, std::span<std::uint32_t, 624> target_state) noexcept {
            for (std::size_t i = 0; i < 624; ++i) {
                target_state[i] = untemper(outputs[i]);
            }
        }
    };

} // namespace CryptoAnalysis
