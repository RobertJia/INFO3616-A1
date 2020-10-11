from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

# get the binary png file
pic = open("myfile.png.bin","rb")

# encode the png file to bytes of data
data = pic.read()

# encode the key
key = "INFO3616INFO3616".encode('utf-8')

# create a ECB mode block cipher encryption with random 16-bytes IV to XOR with png data
cipher = AES.new(key, AES.MODE_ECB)

# this is the iv used
# iv = b64encode(cipher.iv).decode('utf-8')

# encrypt the data with 16-byte block size and pad the remainder with 0
ct_bytes = cipher.encrypt(pad(data, AES.block_size))

# write the encrypted data to output file
outfile = open("myfile.png.bin.enc.bin", "wb")
outfile.write(ct_bytes)
outfile.flush()

# clean up
pic.close()
outfile.close()