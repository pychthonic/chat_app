from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP



key = RSA.generate(2048)

# print(f"public key: {key.publickey().export_key().decode()}\n\n")
# print(f"private key: {key.export_key()}\n\n")



message = "hello hellworld >:)".encode("utf-8")

recipient_key = key.publickey()

#print(f"recipient_key: {recipient_key}")

session_key = get_random_bytes(16)

cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)



cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(message)

string_to_send = enc_session_key + cipher_aes.nonce + tag + ciphertext

print(f"enc_session_key: {enc_session_key.decode('ISO-8859-1')}")
print(f"cipher_aes.nonce: {cipher_aes.nonce}")
print(f"tag: {tag}")
print(f"ciphertext: {ciphertext}")
print(f"string_to_send: {string_to_send.decode('ISO-8859-1')}")

private_key = RSA.import_key(key.export_key())

received_enc_session_key = string_to_send[0:private_key.size_in_bytes()]
received_nonce = string_to_send[
                 private_key.size_in_bytes():private_key.size_in_bytes() + 16]
received_tag = string_to_send[
           private_key.size_in_bytes() + 16:private_key.size_in_bytes() + 32
           ]
received_ciphertext = string_to_send[private_key.size_in_bytes() + 32:]



cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(received_enc_session_key)

cipher_aes = AES.new(session_key, AES.MODE_EAX, received_nonce)

data = cipher_aes.decrypt_and_verify(received_ciphertext, received_tag)

print(f"Decrypted: {data.decode('utf-8')}")




