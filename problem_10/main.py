import os
import sys
import binascii
from Cryptodome.Cipher import AES

plain1 = "################".encode()
plain2 = "#              #".encode()
plain3 = "#    START     #".encode()
plainX = "#     END      #".encode()
plainStart = [plain1, plain2, plain3, plain2, plain1]
plainEnd = [plain1, plain2, plainX, plain2, plain1]
#key = ... # I am not about to tell you!

#cipher = AES.new(key, AES.MODE_ECB)


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



# def transcrypt(nonce, input_text):
#     # the nonce is encrypted first then XORed with a line of plaintext
#     enc_nonce = cipher.encrypt(nonce)
#     ciphertext = run_xor(enc_nonce, input_text)
#     # the result is a line of ciphertext
#     return ciphertext  


# def encrypt_input_file(filename):
#     with open(filename, "r") as infh, open("encrypted.enc", "w") as outfh:
#         i = 0
#         for line in infh:
#             line = line.rstrip("\n")
#             # the nonce repeats from 0 to 9 for every 10 lines of the plaintext
#             nonce = "000000000000000" + str(i)
#             # every line is encrypted individually in his ECB mode
#             res = transcrypt(nonce.encode(), line.encode())
#             outfh.write(str(i) + "," + res + "\n")
#             i = (i + 1) % 10


def my_xor(s1, s2):

    return bytes([a^b for a, b in zip(s1,s2)])

def break_input_file(filename):
    # YOUR JOB STARTS HERE
    encfile = open(filename, 'r')
    decfile = open("decrypted_text", 'w')
    # store all 10 encrypted nonces we found
    encnonce_list = []
    i = 0
    alllines = encfile.readlines()
    # encnonce = res XOR plaintext, so we figure out the 10 encrypted nonce first by using the header and footer info above
    for count, line in enumerate(alllines[:5]):
        ciline_hex = line.rstrip("\n").split(',')[1]
        # convert the ciphertext from hex values to bytes
        ciline = bytes.fromhex(ciline_hex)
        encnonce = my_xor(ciline, plainStart[count])
        encnonce_list.append(encnonce)
    
    for count, line in enumerate(alllines[-5:]):
        #print(line)
        ciline_hex = line.rstrip("\n").split(',')[1]
        # convert the ciphertext from hex values to bytes
        ciline = bytes.fromhex(ciline_hex)
        encnonce = my_xor(ciline, plainEnd[count])
        encnonce_list.append(encnonce)

    #print(encnonce_list)
    for line in alllines:
        ciline_hex = line.rstrip("\n").split(',')[1]
        # convert the ciphertext from hex values to bytes
        ciline = bytes.fromhex(ciline_hex)
        # encline = encnonce XOR plaintext  => plaintext = encline XOR encnonce
        pline = my_xor(ciline, encnonce_list[i])
        decfile.write(pline.decode() + "\n")
        i = (i+1) % 10  
    encfile.close()
    decfile.close()     
    # YOUR JOB ENDS HERE

def main(args):
    if len(args) > 1:
        filename = args[1]
        break_input_file(filename)
    else:
        print("Please provide a file to break!")

if __name__ == '__main__':
    main(sys.argv)
