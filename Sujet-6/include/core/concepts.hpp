#pragma once
#include <concepts>
#include <cstdint>

namespace CryptoCore {
    template<typename T>
    concept PRNG = requires(T g) {
        { g.next_bit() } -> std::same_as<bool>;
        { g.next_u32() } -> std::same_as<std::uint32_t>;
        { g.reset() }    -> std::same_as<void>;
    };
}