#pragma once

#include <cstddef>
#include <cstdint>

/**
 * @file protocol.hpp
 * @brief Constantes partagées du protocole TCP de la PoC d'usurpation de session.
 *
 * Le serveur expose un PRNG MT19937 global : chaque token émis consomme une sortie
 * du générateur, quel que soit le client connecté. C'est cette propriété qui permet
 * à l'attaquant de reconstruire l'état interne à partir de tokens observés chez
 * d'autres utilisateurs, puis de prédire le jeton de session suivant.
 */
namespace SessionProtocol {

    /// Port TCP d'écoute du serveur de session vulnérable.
    constexpr std::uint16_t PORT = 8080;

    /// Opcode client → serveur : demander un nouveau token de session.
    constexpr std::uint8_t OP_REQUEST_TOKEN = 0x01;

    /// Opcode client → serveur : soumettre un token pour authentification.
    constexpr std::uint8_t OP_VERIFY_TOKEN = 0x02;

    /// Nombre de sorties MT19937 nécessaires pour cloner l'état interne complet.
    constexpr std::size_t MT_STATE_SIZE = 624;

    /**
     * Nombre de tokens émis par la victime (Alice) avant l'intervention de l'attaquant.
     * Simule l'observation passive du trafic réseau d'un autre utilisateur.
     */
    constexpr std::size_t VICTIM_OBSERVED_COUNT = 600;

    /// Fichier binaire simulant les tokens interceptés sur le réseau (sortie de la victime).
    constexpr const char* OBSERVED_TOKENS_FILE = "/tmp/poc_observed_tokens.bin";

    /// Fichier binaire contenant le token reçu par la victime lors de sa connexion.
    constexpr const char* VICTIM_LOGIN_TOKEN_FILE = "/tmp/poc_victim_login.bin";

} // namespace SessionProtocol
