# README.md

## Informations Générales

* **Auteur** : Romain Verguet
* **Niveau** : 5ème année - Architecture Logicielle (ESGI)
* **Sujet** : Sujet 6 - Implémentation et cassage de LFSR et générateurs pseudo-aléatoires faibles

---

## 1. Contexte et Objectifs de la PoC

Ce projet est une Preuve de Concept (PoC) démontrant l'insécurité systémique des générateurs de nombres pseudo-aléatoires (PRNG) linéaires non qualifiés pour la cryptographie. L'objectif est d'illustrer qu'un attaquant capable d'intercepter un segment fini de la sortie d'un flux peut cloner mathématiquement l'état interne du générateur et en prédire l'intégralité des valeurs futures.

Le projet implémente et casse deux structures distinctes :

1. Un **LFSR (Linear Feedback Shift Register)** de degré 32 par reconstruction algébrique.
2. Le générateur **Mersenne Twister (MT19937)** par inversion de la fonction de masquage (*untempering*).
3. Un scénario réel d'**usurpation de session** réseau basé sur l'exploitation de jetons prédictibles.

---

## 2. Architecture Technique et Optimisations

Le projet est développé en **C++20** standard sans aucune dépendance externe afin de garantir des performances machines maximales et un contrôle total de la mémoire :

* **Polymorphisme statique (Concepts C++20)** : L'interface des générateurs est validée à la compilation via le concept `CryptoCore::PRNG`, éliminant le coût d'indirection des tables virtuelles (`vtable`).
* **Zéro allocation dynamique** : Les boucles critiques de calcul mathématique et les couches réseaux s'appuient sur des structures statiques de la pile (`std::array`, `std::span`) pour éviter l'overhead du gestionnaire de mémoire (Heap).
* **Vectorisation par mot machine (Bit-packing)** : Le solveur $GF(2)$ stocke les lignes de la matrice augmentée dans des entiers `std::uint64_t`. Les opérations d'élimination linéaire (Pivot de Gauss) s'exécutent en un seul cycle d'horloge via l'opérateur machine `XOR` (`^`).
* **Gestion Réseau RAII** : L'abstraction des sockets POSIX natives applique le principe RAII strict, garantissant la fermeture automatique et sécurisée des descripteurs de fichiers sans fuite de ressources.

---

## 3. Instructions d'Installation et de Compilation

Le projet utilise **Docker** pour compiler statiquement les cibles et les exécuter dans des conteneurs isolés et ultra-légers `scratch`, garantissant une compatibilité totale sans dépendances systèmes (Linux, Windows, macOS).

### Prérequis
* **Docker** et **Docker Desktop** installés et actifs.

### Compilation des images Docker
```bash
# Compiler les différentes cibles dans des conteneurs scratch distincts
docker build --target lfsr_poc -t lfsr_poc .
docker build --target mt19937_poc -t mt19937_poc .
docker build --target session_server -t session_server .
docker build --target session_attacker -t session_attacker .
```

Les conteneurs générés et leurs rôles correspondants :

| Conteneur | Rôle |
|---|---|
| `lfsr_poc` | Partie 1 — Attaque algébrique sur LFSR |
| `mt19937_poc` | Partie 2 — Clonage de MT19937 |
| `session_server` | Partie 3 — Serveur de tokens vulnérable |
| `session_attacker` | Partie 3 — Client attaquant (Bob) et victime (Alice) intégrée |

---

## 4. Utilisation et Validation de la PoC

### Partie 1 : Validation du cassage algébrique du LFSR

Le programme simule la capture de $2n$ bits (64 bits) d'un LFSR de degré 32, résout le système sur $GF(2)$ pour retrouver le polynôme secret et l'état interne, puis affiche la concordance des 100 bits suivants.

```bash
docker run --rm lfsr_poc
```

### Partie 2 : Validation du clonage de MT19937

Le programme intercepte 624 sorties consécutives de 32 bits, applique l'inversion du masquage bit-à-bit, synchronise un générateur local et prédit avec exactitude les 100 valeurs suivantes du flux.

```bash
docker run --rm mt19937_poc
```

### Partie 3 : Scénario réel d'exploitation réseau (Session Hijacking)

Ce scénario met en jeu **deux utilisateurs distincts** :

* **Alice** (`session_victim`) : utilisatrice légitime qui reçoit des tokens de session.
* **Bob** (`session_attacker`) : attaquant qui intercepte passivement les tokens d'Alice, complète sa connaissance du flux PRNG, prédit le prochain token d'Alice et usurpe sa session.

Le serveur utilise un **MT19937 global partagé** : chaque token émis par n'importe quel client consomme une sortie du même générateur. C'est cette propriété qui rend l'attaque possible.

#### Protocole d'exécution et de validation :
```bash
# 1. Créer le volume partagé pour échanger les fichiers de jetons
docker volume create poc_tmp

# 2. Lancer le serveur de session vulnérable
docker run -d --name poc_server session_server

# 3. Alice demande ses premiers jetons (setup)
docker run --rm -v poc_tmp:/tmp --net=container:poc_server --entrypoint /session_victim session_attacker setup

# 4. Lancer l'attaquant Bob pour exécuter l'attaque de session hijacking
docker run --rm -v poc_tmp:/tmp --net=container:poc_server session_attacker

# 5. Nettoyer les ressources
docker rm -f poc_server
docker volume rm poc_tmp
```

Déroulement automatique de `session_attacker` :

1. Lecture des 600 tokens interceptés chez Alice (fichier `/tmp/poc_observed_tokens.bin`).
2. Collecte de 24 tokens supplémentaires en tant que client légitime (Bob) pour atteindre 624 sorties.
3. Clonage de l'état interne MT19937 et prédiction du token suivant d'Alice.
4. Lancement d'Alice (`session_victim login`) qui demande son token au serveur.
5. Vérification que le token prédit correspond exactement à celui reçu par Alice.
6. Usurpation : Bob s'authentifie avec le token d'Alice avant elle.
7. Alice tente de s'authentifier (`session_victim auth`) et est refusée.

*Preuve du concept :* Bob prédit le token de session d'un **autre utilisateur** (Alice) avant même qu'il ne soit émis, s'authentifie avec ce token volé, et Alice se voit refuser l'accès à sa propre session.

---

## 5. Réponses aux Questions du TP

### 5.1 Formalisation de l'attaque LFSR sur $GF(2)$

Un registre à décalage à rétroaction linéaire (LFSR) de degré $n$ génère une suite binaire $y_t$ définie par la relation de récurrence linéaire suivante :

$$y_{t+n} = \sum_{i=0}^{n-1} c_i \cdot y_{t+i} \pmod 2$$

Où les coefficients $c_i \in \{0, 1\}$ représentent la présence ou l'absence d'une connexion sur le polynôme de rétroaction. Si un attaquant observe $2n$ bits consécutifs de la suite ($y_0, y_1, \dots, y_{2n-1}$), il peut poser un système de $n$ équations linéaires indépendantes à $n$ inconnues :

$$\begin{pmatrix}
y_0 & y_1 & \dots & y_{n-1} \\
y_1 & y_2 & \dots & y_{n} \\
\vdots & \vdots & \ddots & \vdots \\
y_{n-1} & y_n & \dots & y_{2n-2}
\end{pmatrix}
\begin{pmatrix}
c_0 \\ c_1 \\ \vdots \\ c_{n-1}
\end{pmatrix}
=
\begin{pmatrix}
y_n \\ y_{n+1} \\ \vdots \\ y_{2n-1}
\end{pmatrix}$$

Ce système opère sur le corps fini $GF(2)$, ce qui implique que l'addition matricielle correspond à l'opérateur logique `XOR` ($\oplus$) et la multiplication à l'opérateur `AND` ($\wedge$). La résolution par élimination de Gauss-Jordan permet d'isoler de manière unique le vecteur des coefficients $c_i$, reconstruisant ainsi parfaitement le polynôme de rétroaction.

### 5.2 Structure de MT19937 et Inversion de la fonction de Tempering

Le Mersenne Twister maintient un état interne composé d'un tableau de 624 entiers non signés de 32 bits. Lors de l'extraction d'un nombre via `next_u32()`, l'algorithme extrait la valeur brute de l'état courant et lui applique une transformation bijective linéaire appelée *tempering* pour en améliorer les propriétés statistiques de distribution. Les opérations successives appliquées à la valeur initiale $x$ pour obtenir la valeur finale $y$ sont :

1. $y_1 = x \oplus (x \gg 11)$
2. $y_2 = y_1 \oplus ((y_1 \ll 7) \wedge \text{0x9D2C5680})$
3. $y_3 = y_2 \oplus ((y_2 \ll 15) \wedge \text{0xEFC60000})$
4. $y = y_3 \oplus (y_3 \gg 18)$

Chaque étape étant une bijection linéaire, elles sont inversibles de manière indépendante en inversant l'ordre d'exécution (de la phase 4 vers la phase 1). L'inversion tire parti du fait que les décalages logiques insèrent des zéros. Par exemple, pour l'étape 4, le décalage de 18 bits vers la droite implique que les 18 bits de poids fort de $y$ sont strictement identiques à ceux de $y_3$. En effectuant un `XOR` entre ces 18 bits connus et la valeur totale de $y$, on annule la transformation pour récupérer les bits de poids faible restants. L'application séquentielle de cette logique (`untemper`) sur 624 valeurs de sortie restaure directement les 624 mots bruts du registre interne.

### 5.3 Analyse de Cas Réels de Vulnérabilités

* **`PHP rand()` / `glibc random()` (historiques)** : Utilisaient historiquement des Générateurs Congruentiels Linéaires (LCG) définis par $X_{n+1} = (A \cdot X_n + C) \pmod M$ ou des variantes simplifiées. Quelques observations suffisent à appliquer l'algorithme d'Euclide étendu pour casser le module et prédire les identifiants de session ou de réinitialisation de mot de passe.

* **`Java Random`** : Repose sur un LCG à 48 bits. Comme les primitives distribuées n'exposent que les 32 bits supérieurs, l'observation de seulement deux sorties consécutives permet de retrouver par force brute les 16 bits manquants en moins d'une milliseconde, compromettant le générateur.

* **Systèmes Embarqués (Génération de Clés Cryptographiques)** : De nombreuses failles proviennent d'une mauvaise initialisation de la graine (*seeding*). Utiliser uniquement l'horloge système au démarrage (`srand(time(NULL))`) réduit l'entropie de recherche à un espace prévisible (la date de démarrage de la machine à la seconde près), ce qui permet à un attaquant distant de mener une recherche exhaustive pour cloner le PRNG.

### 5.4 Propriétés d'un CSPRNG et Mécanismes de Résistance

Pour empêcher le cassage algébrique, un générateur doit posséder des caractéristiques de sécurité cryptographique strictes (CSPRNG) :

1. **Propriété du bit suivant** : Un attaquant connaissant les $k$ premiers bits de la séquence ne doit avoir aucune probabilité supérieure à $50\%$ de deviner le bit $k+1$.
2. **Résistance à la compromission d'état** : Si l'état interne à l'instant $t$ est volé, il doit être mathématiquement impossible de reconstruire les états antérieurs ($t-1$) pour garantir la confidentialité persistante.

#### Pourquoi un CSPRNG (comme ChaCha20) résiste à ces attaques

Des algorithmes comme **ChaCha20** abandonnent la pure linéarité des décalages et des `XOR` au profit d'architectures de type ARX (Addition, Rotation, XOR) appliquées en interne sur plusieurs rounds d'une matrice d'état.

L'introduction de l'**addition modulaire** ($A + B \pmod{2^{32}}$) détruit la linéarité algébrique du système : la propagation de la retenue binaire introduit des dépendances non linéaires d'ordre supérieur. Il devient impossible de modéliser l'évolution du générateur sous forme de système d'équations linéaires sur $GF(2)$ ou d'inverser les étapes par masquage simple. La complexité de la résolution mathématique bascule d'une résolution polynomiale $\mathcal{O}(n)$ à une complexité exponentielle de l'ordre de $\mathcal{O}(2^{256})$, rendant toute tentative de reconstruction computationnellement impossible.

#### Pourquoi `/dev/urandom` résiste à ces attaques

**`/dev/urandom`** est l'interface standard Unix/Linux vers le générateur aléatoire du noyau (basé sur ChaCha20 depuis Linux 5.17, ou AES-CTR auparavant). Contrairement aux PRNG de ce TP, il ne repose pas sur une récurrence linéaire prévisible :

* **Source d'entropie physique** : Le noyau collecte de l'entropie depuis des événements non déterministes (interruptions matérielles, timings disque/réseau, mouvements souris) via le collecteur d'entropie (`crng`).
* **État interne inaccessible** : L'état du générateur noyau n'est jamais exposé aux applications. Seuls des octets dérivés sont fournis via `read()`, sans corrélation linéaire exploitable entre lectures successives.
* **Re-seeding continu** : Le pool d'entropie est régulièrement réapprovisionné, empêchant la reconstruction d'état même en cas de fuite partielle.
* **Aucune reproductibilité** : Deux appels à `/dev/urandom` ne produiront jamais des séquences corrélées, contrairement à `srand(fixed_seed)` utilisé dans cette PoC.

En pratique, toute application cryptographique (génération de clés TLS, tokens de session, IV aléatoires) doit utiliser `/dev/urandom` (ou son équivalent `getrandom(2)`) plutôt qu'un PRNG logiciel non conditionné comme MT19937.
