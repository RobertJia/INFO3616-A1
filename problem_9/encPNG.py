from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

# get the binary png file
pic = open("myfile.png.bin","rb")

# read the png file as bytes of data
data = pic.read()

# encode the key
key = "INFO3616INFO3616".encode('utf-8')

# create an ECB mode block cipher encryption
cipher = AES.new(key, AES.MODE_ECB)

# encrypt the data with 16-byte block size and pad the remainder with 0
ct_bytes = cipher.encrypt(pad(data, AES.block_size))

# write the encrypted data to output file
outfile = open("myfile.png.bin.enc.bin", "wb")
outfile.write(ct_bytes)
outfile.flush()

# clean up
pic.close()
outfile.close()