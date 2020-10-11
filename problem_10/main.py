import os
import sys
import binascii
from Crypto.Cipher import AES

plain1 = "################".encode()
plain2 = "#              #".encode()
plain3 = "#    START     #".encode()
plainX = "#     END      #".encode()
plainStart = [plain1, plain2, plain3, plain2, plain1]
plainEnd = [plain1, plain2, plainX, plain2, plain1]
key = ... # I am not about to tell you!

cipher = AES.new(key, AES.MODE_ECB)


def run_xor(b1, b2):
    if len(b1) != len(b2):
        print("XOR: mismatching length of byte arrays")
        os.exit(-1)
    
    output = []

    for i in range(0, len(b1)):
        x = b1[i] ^ b2[i]
        t = "%x" % x
        if len(t) == 1:
            t = "0" + t
        output.append(t)
    return "".join(output)



def transcrypt(nonce, input_text):

    enc_nonce = cipher.encrypt(nonce)
    ciphertext = run_xor(enc_nonce, input_text)
    return ciphertext



def encrypt_input_file(filename):
    with open(filename, "r") as infh, open("encrypted.enc", "w") as outfh:
        i = 0
        for line in infh:
            line = line.rstrip("\n")
            nonce = "000000000000000" + str(i)
            res = transcrypt(nonce.encode(), line.encode())
            outfh.write(str(i) + "," + res + "\n")
            i = (i + 1) % 10


def break_input_file(filename):
    # YOUR JOB STARTS HERE

    # YOUR JOB ENDS HERE
    pass


def main(args):
    if len(args) > 1:
        filename = args[1]
        break_input_file(filename)
    else:
        print("Please provide an file to break!")

if __name__ == '__main__':
    main(sys.argv)
