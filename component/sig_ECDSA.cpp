#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/hash.h>
#include <pybind11/pybind11.h>
#include <string>

char version[] = "1.0";

const char *getVersion()
{
    return version;
}

class ECDSASignature
{
private:
    Botan::ECDSA_PrivateKey *key;

public:
    ECDSASignature()
    {
        // Initialize RNG
        Botan::AutoSeeded_RNG rng;

        // Create a new EC key
        key = new Botan::ECDSA_PrivateKey(rng, Botan::OID("secp256k1"));
    }

    ~ECDSASignature()
    {
        // Clean up
        delete key;
    }

    void Initialize(const std::string &privateKeyHex)
    {
        // Create the key from hex
        Botan::BigInt bigIntKey = Botan::BigInt::decode(Botan::hex_decode(privateKeyHex));
        key = new Botan::ECDSA_PrivateKey(Botan::DL_Group("secp256k1"), bigIntKey);
    }

    std::string Sign(const std::string &message)
    {
        if (message.empty())
        {
            throw std::runtime_error("Message cannot be empty.");
        }

        // Hash the message (SHA256)
        std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
        hash->update(message);
        Botan::secure_vector<uint8_t> hashOut = hash->final();

        // Initialize RNG
        Botan::AutoSeeded_RNG rng;

        // Sign the hash
        Botan::PK_Signer signer(*key, rng, "EMSA1(SHA-256)");
        Botan::secure_vector<uint8_t> signature = signer.sign_message(hashOut, rng);

        // Get the signature in hexadecimal
        std::string signatureHex = Botan::hex_encode(signature);

        return signatureHex;
    }
};
/*
namespace py = pybind11;

PYBIND11_MODULE(projet_signature_ECDSA, module)
{
module.doc() = "projet_signature_ECDSA 1.0";
module.def("getVersion", &getVersion, "a function returning the version");

py::class_<ECDSASignature>(module, "ECDSASignature", py::dynamic_attr())
.def(py::init<>())
.def("Initialize", &ECDSASignature::Initialize)
.def("Sign", &ECDSASignature::Sign)
.def("__str__", &ECDSASignature::ToString);

// translate C++ exceptions to Python exceptions
py::register_exception_translator([](std::exception_ptr p) {
try {
if (p) std::rethrow_exception(p);
} catch (const std::runtime_error &e) {
PyErr_SetString(PyExc_RuntimeError, e.what());
} catch (const std::exception &e) {
PyErr_SetString(PyExc_Exception, e.what());
}
});
}
*/