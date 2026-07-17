# Stage 1: Compilateur (Alpine Linux)
FROM alpine:3.18 AS builder

# Installer les dépendances nécessaires à la compilation (les packages statiques sont inclus par défaut dans musl-dev/libstdc++-dev)
RUN apk add --no-cache cmake make g++

WORKDIR /src
COPY . .

# Compiler le projet en liant statiquement toutes les bibliothèques
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXE_LINKER_FLAGS="-static" .. && \
    make

# Créer un dossier temporaire vide à copier pour scratch
RUN mkdir /tmp_dir

# --- Stages d'exécution (Scratch) ---

# 1. LFSR PoC
FROM scratch AS lfsr_poc
COPY --from=builder /src/build/lfsr_poc /lfsr_poc
ENTRYPOINT ["/lfsr_poc"]

# 2. MT19937 PoC
FROM scratch AS mt19937_poc
COPY --from=builder /src/build/mt19937_poc /mt19937_poc
ENTRYPOINT ["/mt19937_poc"]

# 3. Session Server
FROM scratch AS session_server
COPY --from=builder /src/build/session_server /session_server
EXPOSE 8080
ENTRYPOINT ["/session_server"]

# 4. Session Victim (Alice)
FROM scratch AS session_victim
COPY --from=builder /src/build/session_victim /session_victim
COPY --from=builder /tmp_dir /tmp
ENTRYPOINT ["/session_victim"]

# 5. Session Attacker (Bob)
FROM scratch AS session_attacker
COPY --from=builder /src/build/session_attacker /session_attacker
COPY --from=builder /src/build/session_victim /session_victim
COPY --from=builder /tmp_dir /tmp
ENTRYPOINT ["/session_attacker"]
