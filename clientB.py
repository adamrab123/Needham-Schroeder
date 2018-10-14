import socket
import sys
import random
import des
import library

# This will serve as Bob in the NS Protocol


#for the purpose of this assignment, both clients know these
HOST = "127.0.0.1"
PORT = 5010

KDC_key = None
MyId = None

#method for printing the options for the client
def printMenuOptions():
    print("Options:")
    print("\t Enter 'quit' to exit")
    print("\t Enter 'wait' wait for a connection")

# method that creates a random 10 bit key
def random10bit():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return int(num,2)

#method that creates a random 10 bit number as a string to serve as our nonce
def nonceGenerator():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return num


#method that runs that diffie helman exchange for the client
def diffieHelman(kdc, PrivateKey):
    # message = kdc.recv(1024).decode('utf8')
    
    #note b is the private key
    #receive public G and P from server
    message = kdc.recv(1024).decode('utf8')
    message = message.split("|")
    publicP, publicG = int(message[1]),int(message[2])
    global MyId
    MyId = message[0]

    #receives the first calculation
    #call this X
    A = int(kdc.recv(1024).decode('utf8'))

    #generate 10 bit key for KDC
    #call this a
    #now it's time for the client to do their step
    #B = g^b mod p
    b = random10bit()
    B = (publicG**b)%publicP

    #now we send this to the server
    kdc.send(str(B).encode())

    #now we do the final calculation
    #S = A^b mod p
    S = (A**b)%publicP
    global KDC_key
    KDC_key = bin(S)[2:].zfill(10)
    #printing here is only for the sake of this assignment
    #would not get done in real life
    print("Established key = ", str(S))


def main():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "127.0.0.1"
    port = 5000

    try:
        soc.connect((host, port))
    except:
        print("Connection error")
        sys.exit()

    #create the key and use it in function call
    Key = random10bit()
    diffieHelman(soc,Key)

    #print the user options

    while True:
        printMenuOptions()

        message = input(" -> ")
        if message == "quit":
            break
        #print the user options
        soc.send(message.encode("utf8"))
        if soc.recv(5120).decode("utf8") == "-":
            pass   # null operation

        
        if message == "list":
            soc.send(message.encode("utf8"))
            userList = soc.recv(1024).decode('utf8')
            print(userList)
        if 'wait' in message:
            mySocket = socket.socket()
            mySocket.bind((HOST,PORT))

            print("Waiting for connection.....")
            #listens for a user to connect
            mySocket.listen(1)
            #getting the user's connection info
            conn, addr = mySocket.accept()
            print ("Connection from: " + str(addr))

            #this means that Alice has initiated NS with the KDC and has now
            #sent us an encrypted envelope with a session key
            package = conn.recv(1024).decode()

            #we decrypte it
            decryptedPackage = library.decrypt(package,KDC_key)
            Ks = decryptedPackage[:10]
            IDa = decryptedPackage[10:18]
            nonce = decryptedPackage[18:]
            #now we send back an an encrypted nonce
            newNonce = nonceGenerator()
            encryptedNonce = library.encrypt(newNonce,Ks)
            conn.send(encryptedNonce.encode())

            # we get an encrypted altered nonce from A
            incomingChangedNonce = conn.recv(1024).decode()
            changedIncomingNonce = library.decrypt(incomingChangedNonce,Ks)

            #if the difference is what we expect (pre-determined), then....
            #we now have a secure encrypted communication!
            if int(changedIncomingNonce,2) == int(newNonce,2) - 1:
                conn.send("VERIFIED".encode())
                while True:
                    data = conn.recv(1024).decode()
                    decryptedMessage = library.decrypt(data,Ks)
                    if not data:
                            break
                    print ("Decrypted Message = " + str(decryptedMessage))
                    message = input("Enter the message you want to encrypt -> ")
                    #encrypting the message using DES
                    finalEncryptedMessage = library.encrypt(message,Ks)
                    #prints the pretty loading bar
                    #sending the message
                    conn.send(finalEncryptedMessage.encode())

    soc.send(b'--quit--')

if __name__ == "__main__":
    main()