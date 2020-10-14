from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES
from base64 import b64encode, b64decode
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
class Principal:

    # key_length: RSA key length in bits this principal will use
    # name: name of principal, save key under "name".der in DER format
    def __init__(self, key_length, name):
        # YOUR TASK STARTS HERE
        self.name = name
        self.key_length = key_length
        self.own_key = self.create_rsa_key(key_length)
        # YOUR TASK ENDS HERE
        with open("{}.der".format(name), "wb") as out_fh:
            out_fh.write(self.own_key.exportKey(format ='DER', pkcs=1))

    # Create RSA key of given key_length
    def create_rsa_key(self, key_length):
        # YOUR TASK STARTS HERE
        rsa_keypair = RSA.generate(key_length)
        # YOUR TASK ENDS HERE
        return rsa_keypair

    # Return public key part of public/private key pair
    def get_public_key(self):
        # YOUR TASK STARTS HERE
        # nothing to do here
        # YOUR TASK ENDS HERE
        public_key = self.own_key.publickey()
        return public_key

    # Receiving means reading a hybrid-encrypted message from a file.
    # Returns: encrypted key (bytes), encrypted message (bytes), IV (bytes),
    # number of padding bytes
    def receive(self, filename):
        # YOUR TASK STARTS HERE
        encfile = open(filename, 'r')
        alllines = encfile.readlines()
        ck_bytes = bytes.fromhex(alllines[0].rstrip("\n"))
        cm_bytes = bytes.fromhex(alllines[1].rstrip("\n"))
        iv_bytes = bytes.fromhex(alllines[2].rstrip("\n"))
        pad_len_int = int(alllines[3].rstrip("\n"))
        # YOUR TASK ENDS HERE
        return [ck_bytes, cm_bytes, iv_bytes, pad_len_int]

    # Sending means writing an encrypted message plus metadata to a file.
    # Line 1: RSA-encrypted symmetric key, as hex string.
    # Line 2: Symmetrically encrypted message, as hex string.
    # Line 3: IV as hex string
    # Line 4: Number of padding bytes (string of int)
    def send(self, filename, msg):
        # YOUR TASK STARTS HERE
        # ...
        encfile = open(filename, 'w')
        ck_hex = msg[0]
        cm_hex = msg[1]
        iv_hex = msg[2]
        pad_len_hex = msg[3]
        encfile.write('\n'.join([ck_hex, cm_hex, iv_hex, str(pad_len_hex)]))
        encfile.close()
        # YOUR TASK ENDS HERE
        pass

# Hybrid Cipher encapsulates the functionality of a hybrid cipher using
# RSA and AES-CBC.
# Key length of AES is a parameter.
class HybridCipher:

    # length_sym: length of symmetric key in bits. Must be 128, 192, or 256.
    # own_key: public/private key pair of owner (principal who can decrypt)
    # remote_pub_key: public key of principal this hybrid cipher is encrypting to
    def __init__(self, length_sym, own_key, remote_pub_key):
        # YOUR TASK STARTS HERE
        # ...
        self.length_sym = length_sym
        self.own_key = own_key
        self.remote_pub_key = remote_pub_key
        # YOUR TASK ENDS HERE
        pass


    # Creates an AES cipher in CBC mode with random IV, and random key
    # Returns: cipher, IV, symmetric key
    def create_aes_cipher(self, length):
        # YOUR TASK STARTS HERE
        # get the key with specified length, randomly
        sym_key = get_random_bytes(int(length/8))
        # create a CBC mode block cipher encryption with random IV to XOR with the plain text data
        cipher = AES.new(sym_key, AES.MODE_CBC)
        # this is the iv used, encoded in base 64
        iv = b64encode(cipher.iv)
        # YOUR TASK ENDS HERE
        return cipher, iv, sym_key


    # Decrypted hybrid-encrypted msg (list of bytes received)
    # Returns: decrypted message with padding removed, as string
    def decrypt(self, msg):
        # YOUR TASK STARTS HERE
        ck_bytes = msg[0]
        cm_bytes = msg[1]
        iv_bytes = msg[2]
        RSAcipher = PKCS1_OAEP.new(self.own_key)
        sym_key = RSAcipher.decrypt(ck_bytes)
        decipher = AES.new(sym_key, AES.MODE_CBC, b64decode(iv_bytes))
        rcvd_msg_dec = unpad(decipher.decrypt(cm_bytes), AES.block_size).decode()
        # YOUR TASK ENDS HERE
        return rcvd_msg_dec


    # remote_pub_key: key pair, sym_key: bytes
    def encrypt_smkey(self, remote_pub_k, sym_key):
        RSAcipher = PKCS1_OAEP.new(remote_pub_k)
        enc_sym_key = RSAcipher.encrypt(sym_key)
        return enc_sym_key
    

    # Encrypts plaintext msg (string) to encrypt in hybrid fashion.
    # Returns: encrypted symmetric key (hex), encrypted message (hex), IV (hex), number of padding bytes
    def encrypt(self, msg):
        # YOUR TASK STARTS HERE
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
        # YOUR TASK ENDS HERE
        return [ck, cm, iv, pad_len]

    # Padding for AES-CBC.
    # Pad up to multiple of block length by adding 0s (as byte)
    # Returns: padded message, number of padding bytes
    def pad(self, msg):
        # YOUR TASK STARTS HERE
        # not using
        padded_msg = ""
        # YOUR TASK ENDS HERE
        return padded_msg

    # Strips padding and converts message to str.
    def strip_pad(self, msg, pad_len_int):
        # YOUR TASK STARTS HERE
        # not using
        msg_unpadded = ""
        # YOUR TASK ENDS HERE
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
    msg = "Hi Bob, it's Alice."
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
