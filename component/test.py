import sig_clePublic
import binascii

# Créez une instance de la classe ECDSAPubKey
macle = sig_clePublic.ECDSAPubKey()

# Initialisez avec une clé privée
<<<<<<< HEAD
macle.initialize("371ADD1C2C324A1278F2412D034005A146D2FA370C6B3C985B133D5C4D97A062EA7FDB202C01DAF04043099544354763290572416B8E22B6B8FF7ED101F6A3C7","Hello, World!")
=======
message = "Hello, World"
message_hex = binascii.hexlify(message.encode()).decode()

macle.initialize("371ADD1C2C324A1278F2412D034005A146D2FA370C6B3C985B133D5C4D97A062EA7FDB202C01DAF04043099544354763290572416B8E22B6B8FF7ED101F6A3C7",message_hex)
>>>>>>> 985cb292089df9f8d24ee3d21f7f667fd55b44e0

# Récupérez la clé publique
print("Cle public : ")
print(macle.getPubKey())
