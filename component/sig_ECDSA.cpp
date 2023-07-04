#include <botan/ecdsa.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/der_enc.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/pkcs8.h>
#include <botan/data_src.h>
#include <botan/pipe.h>
#include <iostream>
//#include <pybind11/pybind11.h>
//#include <pybind11/stl.h>
#include <string>

using namespace std;

class ECDSASignature{
    Botan::AutoSeeded_RNG rng;
    Botan::ECDSA_PrivateKey* key;
public:
    ECDSASignature() {
        key = new Botan::ECDSA_PrivateKey(rng, Botan::EC_Group("secp256k1"));
    }

    void Initialize(const string& privateKey){
        Botan::BigInt bigIntKey(privateKey);
        key = new Botan::ECDSA_PrivateKey(rng, Botan::EC_Group("secp256k1"), bigIntKey);
    }

    string Sign(const string& msg){
        Botan::PK_Signer signer(*key, "EMSA1(SHA-256)");
        signer.update(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        std::vector<uint8_t> hashOut(signer.signature_length(), 0);
        size_t signatureLen = signer.signature_length();
        Botan::secure_vector<uint8_t> signature(hashOut.data(), hashOut.data() + hashOut.size());
        return Botan::hex_encode(signature);
    }
};

int main()
{
    ECDSASignature ecdsaSignature;
    std::string message = "Hello, World!";
    std::string signature = ecdsaSignature.Sign(message);

    std::cout << "Signature: " << signature << std::endl;

    return 0;
}


/*

namespace py = pybind11;

PYBIND11_MODULE(projet_signature_ECDSA, module)
{
module.doc() = "projet_signature_ECDSA 1.0";

py::class_<ECDSASignature>(module, "ECDSASignature")
.def(py::init<const std::string &>())
.def("Sign", &ECDSASignature::Sign);
}
 */