from hashlib import sha256
import hmac

def create_hash_chain(seed, key, length, hash_function, length_tag_bits):
    chain = []
    curr_tag = seed
    for i in range(length):
        digest_maker = hmac.new(key, hash_function)
        digest_maker.update(curr_tag)
        

create_hash_function(111, 111, 10, sha256)
 
if __name__ == "__main__":
 
    from math import log10
    from time import time
 
    def printHexList(intList):
        """Print ciphertext in hex"""
        for index, elem in enumerate(intList):
            if index % 32 == 0:
                print()            
            print "{:02x}".format(elem)
        print()
 
    def printLargeInteger(number):
        """Print long primes in a formatted way"""
        string = "{:02x}".format(number)
        for j in range(len(string)):
            if j % 64 == 0:
                print()
            print string[j]
        print()
 
    def testCase(p, q, msg, nTimes = 1):
        """Execute test case: generate keys, encrypt message and
           decrypt resulting ciphertext"""
        print("Key size: {:0d} bits".format(int(round(log10(p * q) / log10(2)))))
        print("Prime #1:")
        printLargeInteger(p)
        print("Prime #2:")
        printLargeInteger(q)
        print("Plaintext:", msg)
        pk, sk, mod = genRSA(p, q)
        ctext = encrypt(msg, pk, mod)
        print("Ciphertext:")
        printHexList(ctext)
        ptext = decrypt(ctext, sk, p, q)
        print("Recovered plaintext:", ptext, "\n")
 
    # First test: RSA-129 (see http://en.wikipedia.org/wiki/RSA_numbers#RSA-129)
    p1 = 3490529510847650949147849619903898133417764638493387843990820577
    p2 = 32769132993266709549961988190834461413177642967992942539798288533
    #testCase(p1, p2, "The Magic Words are Squeamish Ossifrage", 1000)
   
    # Second test: random primes (key size: 512 to 4096 bits)
    '''
    for n in [64]:    
        t1 = time()
        p5 = getPrime(n)
        t2 = time()
        print("Elapsed time for {:0d}-bit prime ".format(n))
        print("generation: {:0.3f} s".format(round(t2 - t1, 3)))
        t3 = time()
        p6 = getPrime(n)
        t4 = time()
        print("Elapsed time for {:0d}-bit prime ".format(n))
        print("generation: {:0.3f} s".format(round(t4 - t3, 3)))
        testCase(p5, p6, "It's all greek to me")
    '''

    '''
    e,d,n = genRSA_bits(64)
    print e,d,n,n.bit_length()
    cypher = enc(123456,e,n)
    print dec(cypher,d,n)
    '''
