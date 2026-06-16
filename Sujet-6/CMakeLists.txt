cmake_minimum_required(VERSION 3.20)
project(PoCCrypto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-O3 -march=native -Wall -Wextra -Wpedantic)

include_directories(include)

# Cible Partie 1 : LFSR
add_executable(lfsr_poc apps/lfsr_poc_app.cpp src/crypto_analysis/gf2_solver.cpp)

# Cible Partie 2 : Mersenne Twister
add_executable(mt19937_poc apps/mt19937_poc_app.cpp)