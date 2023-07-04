#include <pybind11/pybind11.h>
#include <iostream>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

char version[]="1.0";

const char* getVersion() {
	return version;
}

using namespace std;
class ECDSAPubKey{

public:
        ECDSAPubKey() {}
        ~ECDSAPubKey() {}

    void initialize(const std::string& signature, const std::string& message) {
            signatureHex = signature;
            messageHex = message;
        }

    string getPubKey(){
        std::string publicKeyPointHex;
        if (extractPublicKeyFromSignature(signatureHex, messageHex, publicKeyPointHex)) {
            return publicKeyPointHex;
        }
        return "";
    }

    private :
        std::string signatureHex;
        std::string messageHex;

        bool extractPublicKeyFromSignature(const std::string& signatureHex, const std::string& messageHex, std::string& publicKeyPointHex)
        {
            // Convert messageHex to a binary hash
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, messageHex.c_str(), messageHex.size());
            SHA256_Final(hash, &sha256);

            // Load elliptic curve used for the key
            const EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
            if (group == nullptr) {
                std::cerr << "Error loading elliptic curve." << std::endl;
                return false;
            }

            // Convert hex signature to BIGNUM r and s
            BIGNUM* r = BN_new();
            BIGNUM* s = BN_new();
            BN_hex2bn(&r, signatureHex.substr(0, 64).c_str());
            BN_hex2bn(&s, signatureHex.substr(64, 128).c_str());

            // Create ECDSA_SIG structure from r and s components
            ECDSA_SIG* signature = ECDSA_SIG_new();
            ECDSA_SIG_set0(signature, r, s);

            // Recover the public key from the signature
            EC_KEY* publicKey = EC_KEY_new();
            if (publicKey == nullptr) {
                std::cerr << "Error creating EC_KEY object." << std::endl;
                EC_GROUP_free((EC_GROUP*)group);
                ECDSA_SIG_free(signature);
                BN_free(r);
                BN_free(s);
                return false;
            }

            if (ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, signature, publicKey) != 1) {
                std::cerr << "Error recovering the public key." << std::endl;
                EC_GROUP_free((EC_GROUP*)group);
                EC_KEY_free(publicKey);
                ECDSA_SIG_free(signature);
                BN_free(r);
                BN_free(s);
                return false;
            }

            // Convert public key to hexadecimal format
            char* publicKeyPointHexChar = EC_POINT_point2hex(group, EC_KEY_get0_public_key(publicKey), POINT_CONVERSION_UNCOMPRESSED, nullptr);
            if (publicKeyPointHexChar == nullptr) {
                std::cerr << "Error converting public key to hexadecimal format." << std::endl;
                EC_GROUP_free((EC_GROUP*)group);
                EC_KEY_free(publicKey);
                ECDSA_SIG_free(signature);
                BN_free(r);
                BN_free(s);
                return false;
            }

            publicKeyPointHex = publicKeyPointHexChar;
            return true;
        };

};

namespace py = pybind11;

PYBIND11_MODULE(sig_clePublic,greetings)
{
  greetings.doc() = "sig_clePublic";
  greetings.def("getVersion", &getVersion, "a function returning the version");

    py::class_<ECDSAPubKey>(greetings, "ECDSAPubKey", py::dynamic_attr())
            .def(py::init<>())
            .def("initialize", &ECDSAPubKey::initialize)
            .def("getPubKey", &ECDSAPubKey::getPubKey);
}
