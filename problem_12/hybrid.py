from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from base64 import b64encode, b64decode

class Principal:

    # key_length: RSA key length in bits this principal will use
    # name: name of principal, save key under "name".der in DER format
    def __init__(self, key_length, name):
        self.name = name
        self.key_length = key_length
        self.own_key = self.create_rsa_key(key_length)
        with open("{}.der".format(name), "wb") as out_fh:
            out_fh.write(self.own_key.exportKey(format ='DER', pkcs=1))

    # Create RSA key of given key_length
    def create_rsa_key(self, key_length):
        rsa_keypair = RSA.generate(key_length)
        return rsa_keypair

    # Return public key part of public/private key pair
    def get_public_key(self):
        public_key = self.own_key.publickey()
        return public_key

    # Receiving means reading a hybrid-encrypted message from a file.
    # Returns: encrypted key (bytes), encrypted message (bytes), IV (bytes),
    # number of padding bytes
    def receive(self, filename):
        encfile = open(filename, 'r')
        alllines = encfile.readlines()
        ck_bytes = bytes.fromhex(alllines[0].rstrip("\n"))
        cm_bytes = bytes.fromhex(alllines[1].rstrip("\n"))
        iv_bytes = bytes.fromhex(alllines[2].rstrip("\n"))
        pad_len_int = int(alllines[3].rstrip("\n"))
        return [ck_bytes, cm_bytes, iv_bytes, pad_len_int]

    # Sending means writing an encrypted message plus metadata to a file.
    # Line 1: RSA-encrypted symmetric key, as hex string.
    # Line 2: Symmetrically encrypted message, as hex string.
    # Line 3: IV as hex string
    # Line 4: Number of padding bytes (string of int)
    def send(self, filename, msg):
        encfile = open(filename, 'w')
        ck_hex = msg[0]
        cm_hex = msg[1]
        iv_hex = msg[2]
        pad_len_hex = msg[3]
        encfile.write('\n'.join([ck_hex, cm_hex, iv_hex, str(pad_len_hex)]))
        encfile.close()


# Hybrid Cipher encapsulates the functionality of a hybrid cipher using
# RSA and AES-CBC.
# Key length of AES is a parameter.
class HybridCipher:

    # length_sym: length of symmetric key in bits. Must be 128, 192, or 256.
    # own_key: public/private key pair of owner (principal who can decrypt)
    # remote_pub_key: public key of principal this hybrid cipher is encrypting to
    def __init__(self, length_sym, own_key, remote_pub_key):
        self.length_sym = length_sym
        self.own_key = own_key
        self.remote_pub_key = remote_pub_key

    # Creates an AES cipher in CBC mode with random IV, and random key
    # Returns: cipher, IV (bytes), symmetric key (bytes)
    def create_aes_cipher(self, length):
        # get the key with specified length in bits as a byte string, randomly
        sym_key = get_random_bytes(int(length/8))
        # create a CBC mode block cipher encryption with random IV to XOR with the plain text data
        cipher = AES.new(sym_key, AES.MODE_CBC)
        # this is the iv used, encoded in base 64
        iv = b64encode(cipher.iv)
        return cipher, iv, sym_key

    # Decrypted hybrid-encrypted msg (list of bytes received)
    # Returns: decrypted message with padding removed, as string
    def decrypt(self, msg):
        ck_bytes = msg[0]
        cm_bytes = msg[1]
        iv_bytes = msg[2]
        # create a PKCS1_OAEP cipher with Bob's own key pair for RSA decryption
        RSAcipher = PKCS1_OAEP.new(self.own_key)
        # decrypt the symmetric key using Bob's private key
        sym_key = RSAcipher.decrypt(ck_bytes)
        # create an AES cipher in CBC mode with received iv and the symmetric key decrypted
        decipher = AES.new(sym_key, AES.MODE_CBC, b64decode(iv_bytes))
        # decrypt and unpad the message using the symmetric key        
        rcvd_msg_dec = unpad(decipher.decrypt(cm_bytes), AES.block_size).decode()
        return rcvd_msg_dec

    # remote_pub_key: key pair, sym_key: bytes
    def encrypt_smkey(self, remote_pub_k, sym_key):
        # create a PKCS1_OAEP cipher with Bob's public key for RSA encryption
        RSAcipher = PKCS1_OAEP.new(remote_pub_k)
        # encrypt the symmetric key using Bob public key
        enc_sym_key = RSAcipher.encrypt(sym_key)
        return enc_sym_key

    # Encrypts plaintext msg (string) to encrypt in hybrid fashion.
    # Returns: encrypted symmetric key (hex), encrypted message (hex), IV (hex), number of padding bytes (int)
    def encrypt(self, msg):
        # get the cipher, IV and symmetric key
        cipher_tuple = self.create_aes_cipher(self.length_sym)
        cipher = cipher_tuple[0]
        iv = cipher_tuple[1].hex()
        sym_key = cipher_tuple[2]
        # encrypt the data with specified block size and pad the remainder with 0
        ct_bytes = cipher.encrypt(pad(msg.encode(), AES.block_size))
        cm = ct_bytes.hex()
        ck = self.encrypt_smkey(self.remote_pub_key, sym_key).hex()
        pad_len = (AES.block_size - len(msg)) % AES.block_size
        return [ck, cm, iv, pad_len]

    # Padding for AES-CBC.
    # Pad up to multiple of block length by adding 0s (as byte)
    # Returns: padded message, number of padding bytes
    def pad(self, msg):
        # not using
        padded_msg = ""
        return padded_msg

    # Strips padding and converts message to str.
    def strip_pad(self, msg, pad_len_int):
        # not using
        msg_unpadded = ""
        return msg_unpadded


def main():
    # We create Alice as a principal. In this example, we choose a
    # 2048 bit RSA key.
    alice = Principal(2048, "alice")
    # We create Bob as a principal.
    bob = Principal(2048, "bob")

    # We create a HybridCipher for Alice to use. She uses Bob's public key
    # because he is the receiver. Her own public/private key pair goes in there, too,
    # for completeness.
    a_hybrid_cipher = HybridCipher(256, alice.own_key, bob.get_public_key())

    # Alice has a message for Bob.
    msg = "Hi Bob, it's Alice.\nWe are using hybrid encryption to communicate."
    # Alice uses the hybrid cipher to encrypt to Bob.
    msg_enc = a_hybrid_cipher.encrypt(msg)
    alice.send("msg.enc", msg_enc)

    # Bob receives
    rcv_msg_enc = bob.receive("msg.enc")
    # Bob creates a HybridCipher. He configures it with his own public/private
    # key pair, and Alice's public key for completeness.
    b_hybrid_cipher = HybridCipher(256, bob.own_key, alice.get_public_key())
    # Bob decrypts.
    dec_msg = b_hybrid_cipher.decrypt(rcv_msg_enc)
    print(dec_msg)
    
    if msg == dec_msg:
        print("This worked!")

main()
