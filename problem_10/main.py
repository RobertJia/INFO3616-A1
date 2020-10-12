import os
import sys
import binascii
from Cryptodome.Cipher import AES

# the header and footer can be used to find the encrypted nonces since they use exactly nonces 1 to 10 as the first and last 5 lines
plain1 = "################".encode()
plain2 = "#              #".encode()
plain3 = "#    START     #".encode()
plainX = "#     END      #".encode()
plainStart = [plain1, plain2, plain3, plain2, plain1]
plainEnd = [plain1, plain2, plainX, plain2, plain1]

key = "whatever".encode() #... # I am not about to tell you!

cipher = AES.new(key, AES.MODE_ECB)

def run_xor(b1, b2):
    if len(b1) != len(b2):
        print("XOR: mismatching length of byte arrays")
        os._exit(-1)
    
    output = []

    for i in range(0, len(b1)):
        x = b1[i] ^ b2[i]
        t = "%x" % x
        if len(t) == 1:
            t = "0" + t
        output.append(t)
    return "".join(output)

def transcrypt(nonce, input_text):
    # the nonce is encrypted first then XORed with a line of plaintext
    enc_nonce = cipher.encrypt(nonce)
    # we know from here: ciphertext = encrypted_nonce XOR plaintext
    ciphertext = run_xor(enc_nonce, input_text)
    # the result is a line of ciphertext
    return ciphertext  

def encrypt_input_file(filename):
    with open(filename, "r") as infh, open("encrypted.enc", "w") as outfh:
        i = 0
        for line in infh:
            line = line.rstrip("\n")
            # the nonce repeats from 0 to 9 for every 10 lines of the plaintext
            nonce = "000000000000000" + str(i)
            # every line is encrypted individually in his ECB mode
            res = transcrypt(nonce.encode(), line.encode())
            outfh.write(str(i) + "," + res + "\n")
            i = (i + 1) % 10




# this function XOR 2 byte strings
def my_xor(s1, s2):
    return bytes([a^b for a, b in zip(s1,s2)])

def break_input_file(filename):
    # open the ciphertext file and prepare the output plaintext file
    encfile = open(filename, 'r')
    decfile = open("decrypted_text", 'w')
    # this store all 10 encrypted nonces we found
    encnonce_list = []
    # to ensure that the file cursor doesn't move forward when we read different lines
    alllines = encfile.readlines()
    
    # encnonce = ciphertext XOR plaintext, so we can figure out the 10 encrypted nonce by using the header and footer info above
    # the first 5 lines uses nonce 1 to 5
    for count, line in enumerate(alllines[:5]):
        # preprocessing, get the hex string ciphertext
        ciline_hex = line.rstrip("\n").split(',')[1]
        # convert the ciphertext from hex values to bytes
        ciline = bytes.fromhex(ciline_hex)
        # XOR the ciphertext with the header plaintext to get the first 5 nonces
        # logic: IF ciphertext = encrypted_nonce XOR plaintext THEN encrypted_nonce = ciphertext XOR plaintext
        encnonce = my_xor(ciline, plainStart[count])
        encnonce_list.append(encnonce)
    
    # the last 5 lines uses nonce 6 to 10
    for count, line in enumerate(alllines[-5:]):
        # preprocessing, get the hex string ciphertext
        ciline_hex = line.rstrip("\n").split(',')[1]
        # convert the ciphertext from hex values to bytes
        ciline = bytes.fromhex(ciline_hex)
        # XOR the ciphertext with the header plaintext to get the last 5 nonces:
        # logic: IF ciphertext = encrypted_nonce XOR plaintext THEN encrypted_nonce = ciphertext XOR plaintext
        encnonce = my_xor(ciline, plainEnd[count])
        encnonce_list.append(encnonce)

    i = 0
    for line in alllines:
        # preprocessing, get the hex string ciphertext
        ciline_hex = line.rstrip("\n").split(',')[1]
        # convert the ciphertext from hex values to bytes
        ciline = bytes.fromhex(ciline_hex)
        # XOR the ciphertext with the encrypted nonce to get the plaintext back:
        # logic: IF ciphertext = encrypted_nonce XOR plaintext THEN plaintext = ciphertext XOR encrypted_nonce
        pline = my_xor(ciline, encnonce_list[i])
        decfile.write(pline.decode() + "\n")
        # next nonce index
        i = (i+1) % 10  
    encfile.close()
    decfile.close()     

def main(args):
    if len(args) > 1:
        filename = args[1]
        break_input_file(filename)
    else:
        print("Please provide a file to break!")

if __name__ == '__main__':
    main(sys.argv)
