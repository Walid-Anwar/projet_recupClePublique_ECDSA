import projet_signature_ECDSA

# Remplacez ceci par une clé privée valide
known_private_key = "4b8e29b9b0dddd58a709edba7d6df6c07ebdaf5653e325114bc5318c238f87f0"
known_message = "Hello, World!"

# Test de signature
signer = projet_signature_ECDSA.ECDSASignature()
signer.Initialize(known_private_key)
signature = signer.Sign(known_message)

print("Signature :")
print(signature)

# Vérification de la longueur de la signature
if len(signature) == 128:
    print("Signature test passed.")
else:
    print("Signature test failed: Signature does not have the expected length.")

# Test avec une clé privée invalide
try:
    signer = projet_signature_ECDSA.ECDSASignature()
    signer.Initialize("INVALID_PRIVATE_KEY")
except Exception:
    print("Private key test passed: Exception correctly thrown for invalid private key.")
else:
    print("Private key test failed: No exception thrown for invalid private key.")

# Test avec un message vide
try:
    signer = projet_signature_ECDSA.ECDSASignature()
    signer.Initialize(known_private_key)
    signature = signer.Sign("")
except Exception:
    print("Empty message test passed: Exception correctly thrown for empty message.")
else:
    print("Empty message test failed: No exception thrown for empty message.")
