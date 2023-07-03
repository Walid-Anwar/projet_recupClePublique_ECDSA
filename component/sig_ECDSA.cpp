#include <botan/ecdsa.h>
#include <botan/auto_rng.h>
#include <botan/oid.h>
#include <botan/hex.h>
#include <botan/der_enc.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/pkcs8.h>
#include <botan/data_src.h>
#include <botan/pipe.h>
//#include <pybind11/pybind11.h>
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