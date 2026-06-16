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

### Prérequis

* Un compilateur supportant le standard **C++20** (GCC $\ge$ 11 ou Clang $\ge$ 13) 


* **CMake** (version minimale 3.20)
* Un environnement de build compatible POSIX (Linux, Arch Linux)

### Processus de Build

```bash
# 1. Création du répertoire de build
mkdir build && cd build

# 2. Configuration CMake avec optimisations de niveau 3
cmake -DCMAKE_BUILD_TYPE=Release ..

# 3. Compilation globale du projet
make

```

---

## 4. Utilisation et Validation de la PoC

Quatre binaires distincts sont générés dans le répertoire `build/` :

### Partie 1 : Validation du cassage algébrique du LFSR

Le binaire simule la capture de $2n$ bits (64 bits) d'un LFSR de degré 32, résout le système sur $GF(2)$ pour retrouver le polynôme secret et l'état interne, puis affiche la concordance des 100 bits suivants.

```bash
./lfsr_poc

```

### Partie 2 : Validation du clonage de MT19937

Le binaire intercepte 624 sorties consécutives de 32 bits, applique l'inversion du masquage bit-à-bit, synchronise un générateur local et prédit avec exactitude les 100 valeurs suivantes du flux.

```bash
./mt19937_poc

```

### Partie 3 : Scénario réel d'exploitation réseau (Session Hijacking)

Pour valider l'attaque en conditions réelles, lancez le serveur d'authentification sur un premier terminal, puis exécutez l'attaquant sur un second terminal:

```bash
# Terminal 1 : Lancement du service d'authentification
./session_server

# Terminal 2 : Exécution de la cyberattaque
./session_attacker

```

*Preuve du concept :* L'attaquant collecte 624 jetons à distance via des sockets TCP bruts, calcule localement la valeur exacte du 625ème jeton utilisateur avant son émission par le serveur, et réussit à s'authentifier auprès de l'API avec le jeton piraté.

---

## 5. Réponses aux Questions du TP

### 5.1 Formalisation de l'attaque LFSR sur $GF(2)$

Un registre à décalage à rétroaction linéaire (LFSR) de degré $n$ génère une suite binaire $y_t$ définie par la relation de récurrence linéaire suivante:

$$y_{t+n} = \sum_{i=0}^{n-1} c_i \cdot y_{t+i} \pmod 2$$

Où les coefficients $c_i \in \{0, 1\}$ représentent la présence ou l'absence d'une connexion sur le polynôme de rétroaction. Si un attaquant observe $2n$ bits consécutifs de la suite ($y_0, y_1, \dots, y_{2n-1}$), il peut poser un système de $n$ équations linéaires indépendantes à $n$ inconnues:

# $$\begin{pmatrix}
y_0 & y_1 & \dots & y_{n-1} \
y_1 & y_2 & \dots & y_{n} \
\vdots & \vdots & \ddots & \vdots \
y_{n-1} & y_n & \dots & y_{2n-2}
\end{pmatrix}
\begin{pmatrix}
c_0 \
c_1 \
\vdots \
c_{n-1}
\end{pmatrix}

\begin{pmatrix}
y_n \
y_{n+1} \
\vdots \
y_{2n-1}
\end{pmatrix}$$

Ce système opère sur le corps fini $GF(2)$, ce qui implique que l'addition matricielle correspond à l'opérateur logique `XOR` ($\oplus$) et la multiplication à l'opérateur `AND` ($\wedge$). La résolution par élimination de Gauss-Jordan permet d'isoler de manière unique le vecteur des coefficients $c_i$, reconstruisant ainsi parfaitement le polynôme de rétroaction.

### 5.2 Structure de MT19937 et Inversion de la fonction de Tempering

Le Mersenne Twister maintient un état interne composé d'un tableau de 624 entiers non signés de 32 bits. Lors de l'extraction d'un nombre via `next_u32()`, l'algorithme extrait la valeur brute de l'état courant et lui applique une transformation bijective linéaire appelée *tempering* pour en améliorer les propriétés statistiques de distribution. Les opérations successives appliquées à la valeur initiale $x$ pour obtenir la valeur finale $y$ sont:

1. $y_1 = x \oplus (x \gg 11)$
2. $y_2 = y_1 \oplus ((y_1 \ll 7) \wedge \text{0x9D2C5680})$
3. $y_3 = y_2 \oplus ((y_2 \ll 15) \wedge \text{0xEFC60000})$
4. $y = y_3 \oplus (y_3 \gg 18)$

Chaque étape étant une bijection linéaire, elles sont inversibles de manière indépendante en inversant l'ordre d'exécution (de la phase 4 vers la phase 1). L'inversion tire parti du fait que les décalages logiques insèrent des zéros. Par exemple, pour l'étape 4, le décalage de 18 bits vers la droite implique que les 18 bits de poids fort de $y$ sont strictement identiques à ceux de $y_3$. En effectuant un `XOR` entre ces 18 bits connus et la valeur totale de $y$, on annule la transformation pour récupérer les bits de poids faible restants. L'application séquentielle de cette logique (`untemper`) sur 624 valeurs de sortie restaure directement les 624 mots bruts du registre interne.

### 5.3 Analyse de Cas Réels de Vulnérabilités

* 
**`PHP rand()` / `glibc random()` (historiques)** : Utilisaient historiquement des Générateurs Congruentiels Linéaires (LCG) définis par $X_{n+1} = (A \cdot X_n + C) \pmod M$ ou des variantes simplifiées. Quelques observations suffisent à appliquer l'algorithme d'Euclide étendu pour casser le module et prédire les identifiants de session ou de réinitialisation de mot de passe.


* **`Java Random`** : Repose sur un LCG à 48 bits. Comme les primitives distribuées n'exposent que les 32 bits supérieurs, l'observation de seulement deux sorties consécutives permet de retrouver par force brute les 16 bits manquants en moins d'une milliseconde, compromettant le générateur.
* 
**Systèmes Embarqués (Génération de Clés Cryptographiques)** : De nombreuses failles proviennent d'une mauvaise initialisation de la graine (*seeding*). Utiliser uniquement l'horloge système au démarrage (`srand(time(NULL))`) réduit l'entropie de recherche à un espace prévisible (la date de démarrage de la machine à la seconde près), ce qui permet à un attaquant distant de mener une recherche exhaustive pour cloner le PRNG.



### 5.4 Propriétés d'un CSPRNG et Mécanismes de Résistance

Pour empêcher le cassage algébrique, un générateur doit posséder des caractéristiques de sécurité cryptographique strictes (CSPRNG):

1. **Propriété du bit suivant** : Un attaquant connaissant les $k$ premiers bits de la séquence ne doit avoir aucune probabilité supérieure à $50\%$ de deviner le bit $k+1$.
2. **Résistance à la compromission d'état** : Si l'état interne à l'instant $t$ est volé, il doit être mathématiquement impossible de reconstruire les états antérieurs ($t-1$) pour garantir la confidentialité persistante.

#### Pourquoi un CSPRNG (comme ChaCha20) résiste à ces attaques

Des algorithmes comme **ChaCha20** abandonnent la pure linéarité des décalages et des `XOR` au profit d'architectures de type ARX (Addition, Rotation, XOR) appliquées en interne sur plusieurs rounds d'une matrice d'état.

L'introduction de l'**addition modulaire** ($A + B \pmod{2^{32}}$) détruit la linéarité algébrique du système : la propagation de la retenue binaire introduit des dépendances non linéaires d'ordre supérieur. Il devient impossible de modéliser l'évolution du générateur sous forme de système d'équations linéaires sur $GF(2)$ ou d'inverser les étapes par masquage simple. La complexité de la résolution mathématique bascule d'une résolution polynomiale $\mathcal{O}(n)$ à une complexité exponentielle de l'ordre de $\mathcal{O}(2^{256})$, rendant toute tentative de reconstruction computationnellement impossible.