import des
from time import sleep
import sys 

#function that convers binary to ascii
def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'

#function that convers ascii to binary
def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int.from_bytes(text.encode(encoding, errors), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

#function that is given a strinf of length n and a specified length m
#   and return a list of substrings of length m 
def splitIntoGroups(string,length):
    results = []
    loc = 0
    temp = ""
    while(loc < len(string)):
        temp += string[loc]
        loc += 1
        if loc % length == 0:
            results.append(temp)
            temp = ""
    return results

#function that takes encrypted binary and turns it into the decrypted text 
def decrypt(message,key):
    key = str(key)
    #call the DES class
    toy = des.DES(key)
    #split the binary into 8-bit chunks (needed for DES class)
    entries = splitIntoGroups(message,8)
    decryptedMessages = []
    #decrypt each individual chunk
    for i in range(len(entries)):
        decryption = toy.Decryption(entries[i])
        decryptedMessages.append(decryption)
    #concatenate the decryptions
    decryptedMessage ="".join(decryptedMessages)
    #turn from binary to ASCII
    decryptedMessage = text_from_bits(decryptedMessage)
    return decryptedMessage

#function that takes an ASCII text and turns it into the encrypted binary
def encrypt(message,key):
    # print("TYPE OF KEY = ", type(key))
    #call the DES class
    toy = des.DES(key)
    #turn the ascii to binary
    binary = text_to_bits(message)
    #split the binary into 8-bit chunks (needed for DES class)

    entries = splitIntoGroups(binary,8)

    encryptedEntries = []
    #encrypt each individual chunk
    for i in range(len(entries)):
        encryptedMessage = toy.Encryption(entries[i])
        encryptedEntries.append(encryptedMessage)
    #concatenate the encryptions
    finalEncryptedMessage = "".join(encryptedEntries)
    return finalEncryptedMessage

#function that prints a pretty loading bar for sending the messages
def sending():
    print("\nSending ",end = "")
    for j in range(5):
        sleep(0.4)
        print(".", end = "")
        sys.stdout.flush()
    print(' SENT')