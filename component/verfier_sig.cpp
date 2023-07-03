#include <botan/ecdsa.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/der_enc.h>
#include <botan/pubkey.h>
#include <botan/data_src.h>

#include <string>
#include <iostream>
#include <vector>

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

class ECDSAVerify
{
private:
    Botan::ECDSA_PublicKey* key;

public:
    ECDSAVerify()
    {
        key = nullptr;
    }

    ~ECDSAVerify()
    {
        delete key;
    }

    void Initialize(const std::string &publicKeyHex)
    {
        std::vector<uint8_t> publicKeyBytes = HexToBytes(publicKeyHex);
        Botan::DataSource_Memory pub_key_data(publicKeyBytes);
        key = new Botan::ECDSA_PublicKey(pub_key_data);
    }

    bool Verify(const std::string &message, const std::string &signatureHex)
    {
        std::vector<uint8_t> signatureBytes = HexToBytes(signatureHex);

        Botan::PK_Verifier verifier(*key, "EMSA1(SHA-256)");
        verifier.update(message);

        return verifier.check_signature(signatureBytes);
    }
};

int main()
{
    ECDSAVerify ecdsaVerify;
    std::string publicKeyHex = "04F2CE1E40BEFBEBAF4045F1A6D126B7B949E7D5ADEA33F84A09A904093456F4FD504B1F70755BE4CEF27625B1E6B893E05FFEB361F2971FDA1D6BE5E730A74303";
    std::string message = "Hello, World!";
    std::string signature = "371ADD1C2C324A1278F2412D034005A146D2FA370C6B3C985B133D5C4D97A062EA7FDB202C01DAF04043099544354763290572416B8E22B6B8FF7ED101F6A3C7";

    ecdsaVerify.Initialize(publicKeyHex);

    if (ecdsaVerify.Verify(message, signature)) 
    {
        std::cout << "Signature is valid." << std::endl;
    } 
    else 
    {
        std::cout << "Signature is invalid." << std::endl;
    }

    return 0;
}
