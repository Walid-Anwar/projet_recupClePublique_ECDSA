#include <iostream>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/bn.h>

bool extractPublicKeyFromSignature(const std::string& signatureHex, std::string& publicKeyPointHex)
{
    // Charger la courbe elliptique utilisée pour la clé
    const EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == nullptr) {
        std::cerr << "Erreur lors du chargement de la courbe elliptique." << std::endl;
        return false;
    }

    // Convertir la signature hexadécimale en BIGNUM r et s
    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    BN_hex2bn(&r, signatureHex.substr(0, 64).c_str());
    BN_hex2bn(&s, signatureHex.substr(64, 64).c_str());

    // Créer une structure ECDSA_SIG à partir des composantes r et s
    ECDSA_SIG* signature = ECDSA_SIG_new();
    ECDSA_SIG_set0(signature, r, s);

    // Récupérer la clé publique à partir de la signature
    EC_KEY* publicKey = EC_KEY_new();
    if (publicKey == nullptr) {
        std::cerr << "Erreur lors de la création de l'objet EC_KEY." << std::endl;
        EC_GROUP_free((EC_GROUP*)group);
        ECDSA_SIG_free(signature);
        BN_free(r);
        BN_free(s);
        return false;
    }
    if (EC_KEY_set_group(publicKey, group) != 1) {
        std::cerr << "Erreur lors de l'association de la courbe elliptique à la clé." << std::endl;
        EC_GROUP_free((EC_GROUP*)group);
        EC_KEY_free(publicKey);
        ECDSA_SIG_free(signature);
        BN_free(r);
        BN_free(s);
        return false;
    }
    if (ECDSA_do_recover_key(publicKey, signature) != 1) {
        std::cerr << "Erreur lors de la récupération de la clé publique à partir de la signature." << std::endl;
        EC_GROUP_free((EC_GROUP*)group);
        EC_KEY_free(publicKey);
        ECDSA_SIG_free(signature);
        BN_free(r);
        BN_free(s);
        return false;
    }

    // Convertir la clé publique en format hexadécimal
    const EC_POINT* publicKeyPoint = EC_KEY_get0_public_key(publicKey);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, publicKeyPoint, x, y, nullptr);
    char* xHex = BN_bn2hex(x);
    char* yHex = BN_bn2hex(y);
    publicKeyPointHex = std::string(xHex) + std::string(yHex);

    // Libérer la mémoire
    EC_GROUP_free((EC_GROUP*)group);
    EC_KEY_free(publicKey);
    ECDSA_SIG_free(signature);
    BN_free(r);
    BN_free(s);
    BN_free(x);
    BN_free(y);
    OPENSSL_free(xHex);
    OPENSSL_free(yHex);

    return true;
}

int main() {
    std::string signatureHex = "04F2CE1E40BEFBEBAF4045F1A6D126B7B949E7D5ADEA33F84A09A904093456F4FD504B1F70755BE4CEF27625B1E6B893E05FFEB361F2971FDA1D6BE5E730A74303";
    std::string publicKeyPointHex;

    if (extractPublicKeyFromSignature(signatureHex, publicKeyPointHex)) {
        std::cout << "Clé publique : " << publicKeyPointHex << std::endl;
        return 0;
    }

    return 1;
}
