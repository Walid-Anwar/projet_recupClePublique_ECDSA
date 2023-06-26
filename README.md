# Spécification du composant ECDSAPubKey

**Titre :** Spécification du composant de récupération de la clé publique d'une signature ECDSA

**Auteurs :** MIKOU_Abla & ANWAR_WALID

**Historique des versions :**

- 1.0 (25 Juin 2023) - Première version

---

**Description :**

Une signature ECDSA (Elliptic Curve Digital Signature Algorithm) est une méthode de cryptographie utilisée pour prouver l'authenticité et l'intégrité d'un message numérique. C'est comme une "empreinte digitale" numérique qui atteste qu'un message provient d'une source légitime et qu'il n'a pas été altéré pendant la transmission. La signature ECDSA utilise une paire de clés, une clé privée et une clé publique, qui sont générées mathématiquement. La clé privée est utilisée pour signer le message, tandis que la clé publique est utilisée pour vérifier la signature. Grâce aux propriétés des courbes elliptiques, l'algorithme ECDSA offre une sécurité élevée avec des clés plus courtes par rapport à d'autres algorithmes de signature numérique.

**Contexte :**

La classe ECDSAPubKey est une implémentation en C++ de l'algorithme de récupération de la clé publique d'une signature ECDSA. Elle utilise la bibliothèque OpenSSL, une bibliothèque open-source C pour la cryptographie, qui implémente divers algorithmes de chiffrement, de déchiffrement, et de signature numérique.

**Schéma bloc incluant les composants connexes**

```
[Application] --> [ECDSAPubKey Class] --> [OpenSSL Library]
```

**Interface et interaction avec chaque autre composant :**

La classe ECDSAPubKey fournit une interface vers la bibliothèque OpenSSL. Elle utilise les classes et fonctions fournies par OpenSSL pour récuperer la clé publiaue des signatures ECDSA.

**Résumé :**

```cpp
class ECDSAPubKey {
public:
    ECDSAPubKey();
    ~ECDSAPubKey();
    void initialize(const std::string& signature);
    std::string getPubKey();
};
```
---

**Utilisation du composant**

---

Pour utiliser le composant ECDSAPubKey, vous devez d'abord cloner le dépôt et récupérer les sous-modules nécessaires.

**Clonage du dépôt et récupération des sous-modules :**

```bash
cd component
git submodule init
git submodule update
```
Vous devez aussi installer les fichiers d'en-tête nécessaires pour utiliser OpenSSL en utilisant la commande suivante :

```bash
sudo apt-get install libssl-dev
```

**Compilation :**

Naviguez jusqu'au sous-répertoire `component` et compilez le code à l'aide du makefile.

```bash
cd component 
make
```

**Utilisation python :**

Pour utiliser le composant ECDSAPubKey, vous devez importer le module dans votre script Python.

```python
import sig_clePublic

# Créez une instance de la classe ECDSASignature
macle = sig_clePublic.ECDSAPubKey()

# Initialisez l'instance avec votre signature
macle.Initialize("YOUR_SIGN")

# Récuperer la clé public
cle = macle.getPubKey()

# Affichez la signature
print(cle)
```
Ainsi, vous pouvez utiliser le composant ECDSASignature pour signer des messages à l'aide de l'algorithme ECDSA.


---

**Test :**

**Plan de test :**

Nous testerons les méthodes `getPubKey` de la classe `ECDSASignature` en utilisant une signature en dur.
.
**Programme de test :**

```python
import sig_clePublic

# Créez une instance de la classe ECDSAPubKey
macle = sig_clePublic.ECDSAPubKey()

# Initialisez avec une clé privée
macle.initialize("371ADD1C2C324A1278F2412D034005A146D2FA370C6B3C985B133D5C4D97A062EA7FDB202C01DAF04043099544354763290572416B8E22B6B8FF7ED101F6A3C7")

# Récupérez la clé publique
print("Cle public : ")
print(macle.getPubKey())
```

---

**Fin de la spécification de la Classe ECDSAPubKey.**