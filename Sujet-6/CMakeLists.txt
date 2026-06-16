cmake_minimum_required(VERSION 3.20)
project(PoCCrypto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-O3 -march=native -Wall -Wextra -Wpedantic)

include_directories(include)

# Sources réseau communes
set(NETWORK_SOURCES src/network/socket_raii.cpp)

# Partie 1 : LFSR & Solveur GF(2)
add_executable(lfsr_poc apps/lfsr_poc_app.cpp src/crypto_analysis/gf2_solver.cpp)

# Partie 2 : Mersenne Twister Local
add_executable(mt19937_poc apps/mt19937_poc_app.cpp)

# Partie 3 : Scénario d'Exploitation Réseau (Serveur & Attaquant)
add_executable(session_server apps/session_hijack/server.cpp ${NETWORK_SOURCES})
add_executable(session_attacker apps/session_hijack/attacker.cpp ${NETWORK_SOURCES})