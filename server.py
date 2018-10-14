import socket
import sys
import traceback
import random
from threading import Thread
from time import sleep
import des
import library

def random10bit():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return int(num,2)

def nonceGenerator():
	num = ""
	for i in range(10):
		rand = random.randint(0,1)
		num += str(rand)
	return num

def main():
    start_server()

userKeys = dict()

connections = dict()
numberOfUsers = 0
PublicP = 23
PublicG = 5

# def needhamSchroeder(connection,otherUser):
#     print("ENTERED NS")
#     print(connection)
#     # connection.send("entered".encode())
#     message = connection.recv(1024).decode('utf8')
#     # message = connection.recv(1024).decode('utf8')
#     print("message = ", message)

def needhamSchroeder(package, packageConnection):
    IDa = package[:8]
    print("IDa = ", IDa)
    IDaAsInt = int(IDa)
    IDaAsBinary = bin(IDaAsInt)[2:].zfill(8)
    

    IDb = package[8:16]
    print("IDb = ", IDb)
    IDbAsInt = int(IDa)
    IDbAsBinary = bin(IDaAsInt)[2:].zfill(8)
    nonce = package[16:]
    print("nonce = ", nonce)

    AsKey = userKeys[IDa]
    BsKey = userKeys[IDb]

    Ks = nonceGenerator()
    T = nonceGenerator()
    messageToBeEncrypted = Ks + IDaAsBinary + T
    encryptedMessage = library.encrypt(messageToBeEncrypted,BsKey)
    print(encryptedMessage)

    nextMessage = Ks + IDbAsBinary + T + encryptedMessage
    finalEncryptedMessage = library.encrypt(nextMessage,AsKey)

    return finalEncryptedMessage




def diffieHelman(client):
    print("Initiating Diffie Hellman Connection with client")

    # print(connections)
    user = connections[client.getpeername()]
    # print(user)

    # client.send(user.encode())
    #send the public P and public G to the client
    message = "{}|{}|{}".format(user,PublicP,PublicG)
    client.send(message.encode())

    # print("here")
    
    #generate 10 bit key for KDC
    #call this a
    a = random10bit()

    #calcualtes the first step
    #A = g^a mod p
    #send that to the client
    A = (PublicG**a)%PublicP
    client.send(str(A).encode())

    #receives the client calculation
    B = int(client.recv(1024).decode('utf8'))
    # print("B : ", B)
    # print("now here")
    #do final calculation to get shared key
    #S = B^a mod p
    S = (B**a)%PublicP
    userKeys[user] = bin(S)[2:].zfill(10)
    print("Established key = ", str(S))

def start_server():
    host = "127.0.0.1"
    port = 5000         # arbitrary non-privileged port

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire
    print("Socket created")

    try:
        soc.bind((host, port))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()

    soc.listen(5) # queue up to 5 requests
    print("Socket now listening...")

    # infinite loop- do not reset for every requests
    while True:
        connection, address = soc.accept()
        ip, port = str(address[0]), str(address[1])
        if connection.getpeername() not in connections.keys():
            global numberOfUsers 
            numberOfUsers += 1
            connections[connection.getpeername()] = str(numberOfUsers).zfill(8)
        try:
            Thread(target=client_thread, args=(connection, ip, port)).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()
        
            
        user = connections[connection.getpeername()]
        print("\nUser " + str(user) + " connected with " + ip + " on port " + port)
    soc.close()


def client_thread(connection, ip, port, max_buffer_size = 5120):
    is_active = True
    diffieHelman(connection)

    while is_active:
        client_input = receive_input(connection, max_buffer_size)
        print("client input = ", client_input)
        user = connections[connection.getpeername()]
        if "quit" in client_input:
            # print(connections[connection.getpeername()])
            connections[connection.getpeername()] = None
            connection.close()
            print("User " + str(user) + " CLOSED their connection")
            is_active = False
        elif 'list' in client_input:
            output = ""
            print(connection.getpeername())
            if len(connections)==1:
                output = "You are the only user"
                connection.send(output.encode())
            else:
                for user in connections:
                    if connections[connection.getpeername()] == None:
                        pass
                    if user != connection.getpeername():
                        output += str(connections[user]) + ": "
                        output += str(user) + "\n"
                    else:
                        output += str(connections[user]) + ": "
                        output += "YOU \n"
                print("output: ",output)
                connection.send(output.encode())
            # connection.sendall("-".encode("utf8"))
        elif 'connect' in client_input:
            # print("TRYING TO START NEEDHAM SCHROEDER")
            # print(client_input)
            package = client_input.split("|")[1]
            messageToA = needhamSchroeder(package,connection)
            # print("message to A = ", messageToA)
            connection.send(messageToA.encode())
            # print(connections)
            # print("client input = ", client_input)
            # otherUser = client_input.split("|")[1]
            # print("sanity")
            # message = connection.recv(1024).decode('utf8')
            # print("message = ", message)
            # # needhamSchroeder(connection,otherUser)
        else:
            print("User " + str(user) + " sent: {}".format(client_input))
            connection.sendall("-".encode("utf8"))


def receive_input(connection, max_buffer_size):
    client_input = connection.recv(max_buffer_size)
    client_input_size = sys.getsizeof(client_input)

    if client_input_size > max_buffer_size:
        print("The input size is greater than expected {}".format(client_input_size))

    decoded_input = client_input.decode("utf8").rstrip()  # decode and strip end of line
    return decoded_input


if __name__ == "__main__":
    main()