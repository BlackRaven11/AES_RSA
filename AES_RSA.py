from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Generate RSA key pair
rsa_key = RSA.generate(2048)
rsa_public_key = rsa_key.publickey()

# Generate AES key
aes_key = get_random_bytes(16)

# Message to encrypt
message = "Hello, World!"

# Encrypt using AES
cipher = AES.new(aes_key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(message.encode())
nonce = cipher.nonce

# Encrypt AES key using RSA public key
rsa_cipher = PKCS1_OAEP.new(rsa_public_key)
encrypted_aes_key = rsa_cipher.encrypt(aes_key)

# Print the encrypted data
print("Encrypted AES Key:", encrypted_aes_key)
print("AES Ciphertext:", ciphertext)
print("AES Tag:", tag)
print("AES Nonce:", nonce)

# Decrypt AES key using RSA private key
decryption_cipher = PKCS1_OAEP.new(rsa_key)
decrypted_aes_key = decryption_cipher.decrypt(encrypted_aes_key)

# Decrypt using AES
decipher = AES.new(decrypted_aes_key, AES.MODE_EAX, nonce=nonce)
decrypted_message = decipher.decrypt_and_verify(ciphertext, tag).decode()

# Print the decrypted data
print("Decrypted Message:", decrypted_message)