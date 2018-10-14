# Needham-Schroeder Protocol

CSCI 4230: Cryptography and Network Security, Homework 2

### The Code

This code was written in Python 3. There are 3 Python files in this repository:

* server.py: This will serve as our main server for this cryptosystem, and will act as our Key Distribution Center (KDC). The server will have the ability to use Diffie-Hellman to create trusted session keys with each client that connects to it, as well as perform the Needham-Schroeder protocol to connect 2 clients together for a secure connected chat.
* client.py: This will serve as the connection client A (e.g. Alice) uses to connect to the KDC for communication. It will connect the user to the KDC using Diffie-Hellman and later allow the user to connect to other users.
* clientB.py: This will serve as the connection client B (e.g. Bob) uses to connect to the KDC for communication. It will allow the user to connect to other users using Needham-Schroeder for a secure communication

### Running The Code

First you must cd into the Needham-Schroeder folder

To run the code, first run the server.py file. This file serves as our KDC

```
python server.py
```

The code declares the host IP and port with the following two lines:

> host = "127.0.0.1"
> port = 5000

These can be changed to any value.

**NOTE: these must match across server.py and client.py**

The code will display the following in the terminal until a user connects:

> Socket created
> Socket now listening....

Now, run the client.py file

```
python client.py
```

This will initiate the Diffie-Hellman protocol and create a session key between the KDC and the client. 

The user will have instructions displayed on the terminal screen, telling you what their options are (note: all commands are case insensitive):

- `'quit'` allows the user to quit the application and be disconnected from the server
- `'list'` will list out all currently connected users. It will include you as well by displaying a "YOU" in the respective row
- `'connect|id'` allows the user to request to connect to the user specified by "id"

Now, run the client.py file

```
python clientB.py
```

This will initiate the Diffie-Hellman protocol and create a session key between the KDC and the client. This can now be used as the client that waits for client A to connect to create the secure chat.

The user will have instructions displayed on the terminal screen, telling you what their options are (note: all commands are case insensitive):

- `'quit'` allows the user to quit the application and be disconnected from the server
- `'wait'` will create a "waiting period" in which B waits for A to initiate the KDC protocol

### Overview/Simplified Instructions

To easily run the program, run the `'server.py'` file first. Next, run  `'clientB.py' `and selected the  `'wait'` command. Next, run  `'client.py'` and select  `'list'` to see who is currently connected. You will see a  `'00000001'` option. To initiate communication with that user, type " `'connect|00000001'`". This will create the secure connection using Needham-Schroeder and the terminals for  `'client.py'` and  `'clientB.py'` will now serve as a secure chat.

### How Diffie Hellman is Used

The following steps are used for this procedure:

1. The KDC and the client agree to a modulus p = 23 and base = 5 (a primitive root of 23). Note: these numbers can be different. Just make sure p is a prime and g is a primitive root modulo p.

2. The KDC chooses a secret integer a (in our case a random 10-bit number). The KDC then computes A = g<sup>a</sup> mod p and sends it to the client

3. The client chooses a secret integer a (again a random 10-bit number). The client then computes B = g<sup>b</sup> mod p and sends it to the client

4. The KDC now S = B<sup>a</sup> and the client computes S = A<sup>b</sup>. This will be the shared key the KDC and the client use from now on. To see why the two are the same, refer to explanation below).

From properties of modulus, B<sup>a</sup> = A<sup>b</sup>. This is because A<sup>b</sup> mod p = g<sup>ab</sup> mod p = g<sup>ba</sup> mod p = B<sup>a</sup> mod p. In other words, (g<sup>a</sup>  mod p)<sup>b</sup> mod p = (g<sup>b</sup>  mod p)<sup>a</sup> mod p.

It should also be noted that only a,b, and g<sup>ab</sup> mod p = g<sup>ba</sup> mod p are kept secret. All the other values (p,g, g<sup>a</sup> mod p, g<sup>b</sup> mod p ), are public. This is an example of the discrete logarithm problem. For small numbers like these, the shared key can be computed. However, for primes of at least 600 digits,

### How Needham Schroeder is Used

The Needham-Schroeder can be split up into 6 main steps:

1. Person A needs to message the KDC with the following: IDa(their ID), IDb (the id of the person they wish to talk to), and a nonce
2. The KDC now encrypts that information, and needs to concatenate it along with other information in the following form:  `Key_A[Ks||IDb||N1||Key_B[Ks||IDa|| N2]]`.  This is sent back to A.
3. A, which knows  `Key_A`, can decrypt the package. This gives A access to the session key as well as the ID belonging to B. A now sends the encrypted part to B (this is encrypted with B's key) so B can decrypt it.
4. B can now decrypt what it received from A. This means it now has access to the session key and the ID belonging to A. The next step is to verify that A is a legitimate user (not an impersonation). To test this, B encrypts a nonce with the session key (meaning A can decrypt it), and sends that over to A. It will expect A to send back the value of the sent nonce minus 1 (this was pre-picked by A and B). 
5. A receives the encrypted nonce, and decrypts it. It then subtracts 1, re-encrypts it with the shared session key, and sends it back to B.
6. B receives the altered nonce. If the value is as expected, the A and B will be connected to a secure chatroom. This chatroom is secure because it uses the shared session key as the private key used in the encryption. Therefore the messages can only be read by A and B.

### Security from Replay Attacks

The typical Needham-Schroeder protocol is vulnerable to a replay attack if an old session key has been compromised. To combat this, this implementation uses a modified version of the Neuman 93 protocol (similar to the Denning 81 protocol's timestamp implementation but it uses a nonce) . This involves adding a second nonce when the KDC sends the information back to the requesting user. By adding this bit of randomness to our string, we make it much harder to reverse our encryption, and thus prevent replay attacks.

### References

1. The server/networking backend used here references the following tutorial: https://www.techbeamers.com/python-tutorial-write-multithreaded-python-server/
