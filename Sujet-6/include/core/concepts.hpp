#pragma once

#include <concepts>
#include <cstdint>

/**
 * @file concepts.hpp
 * @brief Concept C++20 validant l'interface commune des générateurs pseudo-aléatoires.
 *
 * Tout type satisfaisant PRNG peut être utilisé dans les démonstrations d'attaque
 * sans indirection dynamique (pas de vtable, résolution à la compilation).
 */
namespace CryptoCore {

    template<typename T>
    concept PRNG = requires(T g) {
        { g.next_bit() } -> std::same_as<bool>;
        { g.next_u32() } -> std::same_as<std::uint32_t>;
        { g.reset() }    -> std::same_as<void>;
    };

} // namespace CryptoCore
