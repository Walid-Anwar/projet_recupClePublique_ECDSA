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

    std::cerr << "Chargement de la courbe elliptique : OK" << std::endl;
    // Convertir la signature hexadécimale en BIGNUM r et s
    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    BN_hex2bn(&r, signatureHex.substr(0, 64).c_str());
    BN_hex2bn(&s, signatureHex.substr(64, 64).c_str());

    std::cerr << "Convertissement de HEXA à BIGUM : OK" << std::endl;


    // Créer une structure ECDSA_SIG à partir des composantes r et s
    ECDSA_SIG* signature = ECDSA_SIG_new();
    ECDSA_SIG_set0(signature, r, s);


    std::cerr << "Création d'une structure ECDSA_SIG à partir des composantes r et s: OK" << std::endl;


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

    std::cerr << "Récupération des composants à partir de la signature : OK" << std::endl;

    if (EC_KEY_set_group(publicKey, group) != 1) {
        std::cerr << "Erreur lors de l'association de la courbe elliptique à la clé." << std::endl;
        EC_GROUP_free((EC_GROUP*)group);
        EC_KEY_free(publicKey);
        ECDSA_SIG_free(signature);
        BN_free(r);
        BN_free(s);
        return false;
    }

    std::cerr << "Association courbe : OK" << std::endl;

    // Récupérer la clé publique à partir de la signature
    EC_POINT* publicKeyPoint = EC_POINT_new(group);
    if (publicKeyPoint == nullptr) {
        std::cerr << "Erreur lors de la création de l'objet EC_POINT." << std::endl;
        EC_GROUP_free((EC_GROUP*)group);
        EC_KEY_free(publicKey);
        ECDSA_SIG_free(signature);
        BN_free(r);
        BN_free(s);
        return false;
    }
    if (EC_POINT_mul(group, publicKeyPoint, r, nullptr, nullptr, nullptr) != 1) {
        std::cerr << "Erreur lors de la multiplication du point." << std::endl;
        EC_GROUP_free((EC_GROUP*)group);
        EC_KEY_free(publicKey);
        ECDSA_SIG_free(signature);
        BN_free(r);
        BN_free(s);
        EC_POINT_free(publicKeyPoint);
        return false;
    }
    if (EC_POINT_mul(group, publicKeyPoint, nullptr, publicKeyPoint, s, nullptr) != 1) {
        std::cerr << "Erreur lors de la multiplication du point." << std::endl;
        EC_GROUP_free((EC_GROUP*)group);
        EC_KEY_free(publicKey);
        ECDSA_SIG_free(signature);
        BN_free(r);
        BN_free(s);
        EC_POINT_free(publicKeyPoint);
        return false;
    }

    // Convertir la clé publique en format hexadécimal
    char* publicKeyPointHexChar = EC_POINT_point2hex(group, publicKeyPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr);
    if (publicKeyPointHexChar == nullptr) {
        std::cerr << "Erreur lors de la conversion de la clé publique en format hexadécimal." << std::endl;
        EC_GROUP_free((EC_GROUP*)group);
        EC_KEY_free(publicKey);
        ECDSA_SIG_free(signature);
        BN_free(r);
        BN_free(s);
        EC_POINT_free(publicKeyPoint);
        return false;
    }
    publicKeyPointHex = publicKeyPointHexChar;

    // Libérer la mémoire
    EC_GROUP_free((EC_GROUP*)group);
    EC_KEY_free(publicKey);
    ECDSA_SIG_free(signature);
    BN_free(r);
    BN_free(s);
    EC_POINT_free(publicKeyPoint);
    OPENSSL_free(publicKeyPointHexChar);

    return true;
}

int main()
{
    std::string signatureHex = "04F2CE1E40BEFBEBAF4045F1A6D126B7B949E7D5ADEA33F84A09A904093456F4FD504B1F70755BE4CEF27625B1E6B893E05FFEB361F2971FDA1D6BE5E730A74303";
    std::string publicKeyPointHex;

    std::cout << "Début d'éxecution : " << std::endl;
    std::cout << "Signature en hexa : " << signatureHex << std::endl;


    if (extractPublicKeyFromSignature(signatureHex, publicKeyPointHex)) {
        std::cout << "Clé publique : " << publicKeyPointHex << std::endl;
        return 0;
    }

    return 1;
}