import sys

class DES:
	def __init__(self,key):

		self.key = key
		#provided sbox 0
		self.s0 = [[1, 0, 3, 2],
					[3, 2, 1, 0],
					[0, 2, 1, 3],
					[3, 1, 3, 2]]
		#provided sbox 1
		self.s1 = [[0, 1, 2, 3],
				     [2, 0, 1, 3],
				     [3, 0, 1, 0],
				     [2, 1, 0, 3]]

	#comes in as a 4bit key (called binary)
	#1st and last index turn into the row index
	#2nd and 3rd index turns into the col index
	def getSboxEntry(self, binary,sbox):

		#1st and last index indicate the row index of the sbox
		row = binary[0] + binary[3]
		#2nd and 3rd index indeicate the column index of the sbox
		col = binary[1] + binary[2]
		#converting from binary string to integer for both
		row = int(row,2)
		col = int(col,2)
		if sbox == 0:
			binary = bin(self.s0[row][col])[2:]
			#makes sure it isn't a length 1 binary
			if len(binary) == 1:
				binary = "0" + binary
			return binary
		else:
			binary = bin(self.s1[row][col])[2:]
			#makes sure it isn't a length 1 binary
			if len(binary) == 1:
				binary = "0" + binary
			return binary

	#expands they key from 4 bits to 8 bits
	def fFunction(self,key, k):
		#expansion step
		expansion = key[3]+key[0]+key[1]+key[2]+key[1]+key[2]+key[3]+key[0]

		#XORs the 8bit key with the 8 bit key from k value generator
		XOR = bin((int(expansion,2)^int(k,2)))[2:]
		XOR = self.padding(XOR,8)

		left = XOR[:4]
		right = XOR[4:]

		#calls the S function to get the entries from s boxes
		S0 = self.getSboxEntry(left, 0)
		S1 = self.getSboxEntry(right, 1)

		#concatenates them together
		p4 = S0 + S1

		#permutes them in the order 2431 (new 4 bit number)
		p4 = p4[1]+p4[3]+p4[2]+p4[0]

		return p4

	#give it a 10 bit key
	#permutes it in the order we are given 3 5 2 7 4 10 1 9 8 6
	#splits the key into a left and a right
	#left shift both keys (means you rotate once to the left and pop the front to the back)
	#combine the numbers and permute with the order to create k1
	#left shift again and combine the numbers without permutation to create k2
	def kValueGenerator(self, key):
		#initial permuation
		newKey = key[2] + key[4] + key[1] + key[6] + key[3] + key[9] + key[0] + key[8] + key[7] + key[5]
		#splitting the key into the first and second half
		left = newKey[0:5]
		right = newKey[5:]
		#left shifting the first key
		leftShift = left[1:] + left[0]
		#left shifting the second key
		rightShift = right[1:] + right[0]

		#creating k1 by combinig the shifts and permuting
		k1 = leftShift + rightShift
		k1Permuted = k1[5] + k1[2] + k1[6] + k1[3] + k1[7] + k1[4] + k1[9] + k1[8]

		#perfroming a second left shit on the first key
		leftShiftTwice = leftShift[1:] + leftShift[0]
		#performing a second left shift on the second key
		rightShiftTwice = rightShift[1:] + rightShift[0]

		#creating k1 by combining the new shifts and permuting
		k2 = leftShiftTwice + rightShiftTwice
		k2Permuted = k2[5] + k2[2] + k2[6] + k2[3] + k2[7] + k2[4] + k2[9] + k2[8]

		#returning k1 and k2
		return(k1Permuted,k2Permuted)

	#permutes the original key according to the given order 2 6 3 1 4 8 5 7
	def initialPermutation(self,key):
		newKey = key[1] + key[5] + key[2] + key[0] + key[3] + key[7] + key[4] + key[6]
		return newKey

	#permutes the encryption back to the oroginal permutaion
	def reversePermutation(self,key):
		newKey = key[3] + key[0] + key[2] + key[4] + key[6] + key[1] + key[7] + key[5]
		return newKey

	#function that adds padding to make sure the binary is the right length
	#for example if a 4 bit binary is wanted and we get 101 it makes it 0101
	def padding(self,string,length):
		if len(string) == length:
			return string
		while(len(string) < length):
			string = "0" + string
		return string

	#runs through one round of encryption
	#@param string is the 8 bit key
	def Encryption(self,string):
		#goes through initial permutation
		permString = self.initialPermutation(string)
		#splits into two 4 bit strings, A and B
		left = permString[0:4]
		right = permString[4:]
		k1,k2 = self.kValueGenerator(self.key)

		firstFOutput = self.fFunction(right,k1)

		#XORS A and F(B,K1)
		firstXOR = bin((int(left,2)^int(firstFOutput,2)))[2:]
		firstXOR = self.padding(firstXOR, 4)
		secondFOutput = self.fFunction(firstXOR,k2)

		#XORS B and F(XOR(A,F(B,K1)),K2)
		secondXOR = bin((int(right,2)^int(secondFOutput,2)))[2:]
		secondXOR = self.padding(secondXOR, 4)
		output = secondXOR + firstXOR
		
		#reverse the initial permutation
		output = self.reversePermutation(output)
		return output


	#runs through one round of decryption
	def Decryption(self,string):
		#goes through initial permutation
		permString = self.initialPermutation(string)
		#splits into two 4 bit strings, A and B
		left = permString[0:4]
		right = permString[4:]
		k1,k2 = self.kValueGenerator(self.key)

		firstFOutput = self.fFunction(right,k2)

		#XORS A and F(B,K1)
		firstXOR = bin((int(left,2)^int(firstFOutput,2)))[2:]
		firstXOR = self.padding(firstXOR, 4)
		secondFOutput = self.fFunction(firstXOR,k1)

		#XORS B and F(XOR(A,F(B,K1)),K2)
		secondXOR = bin((int(right,2)^int(secondFOutput,2)))[2:]
		secondXOR = self.padding(secondXOR, 4)
		output = secondXOR + firstXOR

		#reverse the initial permutation
		output = self.reversePermutation(output)
		return output