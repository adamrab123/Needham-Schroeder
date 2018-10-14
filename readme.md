# Needham-Schroeder Protocol

### The Code

This code was written in Python 3. There are 2 Python files in this repository:

* server.py: This will serve as our main server for this cryptosystem, and will act as our Key Distribution Center (KDC). The server will have the ability to use Diffie-Hellman to create trusted session keys with each client that connects to it, as well as perform the Nedeham-Schroeder protocol to connect 2 clients together for a secure connected chat.
* client.py: This will serve as the connection the clients use to connect to the KDC for communication. It will connect the user to the KDC using Diffie-Hellma and later allow the user to connect to other users.

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

This will initiate the Diffie-Hellman protocol and create a session key between the KDC and the client. This will happen for every client.py file that is run gor a client

### How Diffie Hellman is Used

The following steps are used for this procedure:

1. The KDC and the client agree to a modulus p = 23 and base = 5 (a primitive root of 23). Note: these numbers can be different. Just make sure p is a prime and g is a primitive root modulo p.

2. The KDC chooses a secret integer a (in our case a random 10-bit number). The KDC then computes A = g<sup>a</sup> mod p and sends it to the client

3. The client chooses a secret integer a (again a random 10-bit number). The client then computes B = g<sup>b</sup> mod p and sends it to the client

4. The KDC now S = B<sup>a</sup> and the client computes S = A<sup>b</sup>. This will be the shared key the KDC and the client use from now on. To see why the two are the same, refer to explanation below).



   From properties of modulus, B<sup>a</sup> = A<sup>b</sup>. This is because A<sup>b</sup> mod p = g<sup>ab</sup> mod p = g<sup>ba</sup> mod p = B<sup>a</sup> mod p. In other words, (g<sup>a</sup>  mod p)<sup>b</sup> mod p = (g<sup>b</sup>  mod p)<sup>a</sup> mod p.

   It should also be noted that only a,b, and g<sup>ab</sup> mod p = g<sup>ba</sup> mod p are keps secret. All the other values (p,g, g<sup>a</sup> mod p, g<sup>b</sup> mod p ), are public. This is an example of the discrete logarithm problem. For small numbers like these, the shared key can be computed. However, for primes of at least 600 digits,

### How Needham Schroeder is Used



### References

1. The server/networking backend used here references the following tutorial: https://www.techbeamers.com/python-tutorial-write-multithreaded-python-server/
2. 
