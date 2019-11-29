from Crypto.PublicKey import RSA
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256


# Function to generate public and private key for a user. Only first login to application
def make_and_save_user_rsa(passphrase):
    # generate a public and private key pair
    key = RSA.generate(2048)

    # encrpt key with passphrase using scrypt algo and store it in a file for later use
    encrypted_key = key.export_key(passphrase=passphrase, pkcs=8, protection="scryptAndAES128-CBC")

    file_out = open("rsa_key.bin", "wb")
    file_out.write(encrypted_key)


# Load rsa key from storage to memory
def load_user_rsa(passphrase):
    encoded_key = open("rsa_key.bin", "rb").read()
    key = RSA.import_key(encoded_key, passphrase=passphrase)
    return key


# generate new session key to encypt the chat
def make_session_key():
    return get_random_bytes(16)


def encypt_session_key(session_key, other_user_pub):
    # Load other users public key
    recipient_key = RSA.import_key(other_user_pub)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    return enc_session_key


def decrypt_session_key(encypted_session_key, my_private_key):
    # Load RSA
    private_key = RSA.import_key(my_private_key)

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(encypted_session_key)

    return session_key


def encypted_message(session_key, message):
    data = message.encode("utf-8")

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    return (cipher_aes.nonce, tag, ciphertext)


def decypt_message(session_key, nonce, tag, ciphertext):
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return data.decode("utf-8")


def hash_message(plain_text):
    return SHA256.new(data=plain_text.encode("utf-8")).digest()


# DO NOT include in actual code
__other_user_rsa = RSA.generate(2048)


def ask_other_user_public_key():
    # TODO This should ask users public key over the network.
    other_user_pub = __other_user_rsa.publickey().export_key()

    return other_user_pub
