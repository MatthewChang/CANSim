import hashlib
import math
import random
import hmac
import array
import binascii

class HashChain:
    ''' Creates a hash chain with given:
            initial value (seed)
            length of chain (length)
            size in bytes of each tag in the chain (size_tag)
            To define the HMAC/keyed hash function a key
                and hash function (hmac_key and hash_function)
            Note: hash_function must be string of the function
                name from Python's hashlib (e.g. 'sha256')
                and key must be a string
    '''
    def __init__(self, seed, length, size_tag, hmac_key, hash_function_str):

        assert size_tag > 0 and length > 1
        self.chain = [seed] #ordered list of authentication tags
        self.size_tag = size_tag
        self.seed = seed
        self.chain_length = length
        self.hmac_key = hmac_key
        self.hash_function = getattr(hashlib, hash_function_str)
        self.is_stale = False #tracks whether the chain is used up

        curr_tag = seed
        for i in range(length):
            digest_maker = hmac.new(hmac_key, curr_tag, self.hash_function)
            tag = digest_maker.digest()[0:size_tag]
            self.chain.append(tag)
            curr_tag = tag
        self.chain.reverse()
        self.ptr = 0 #pointer to current (unused) position in authentication chain

    def get_init_tag(self):
        assert self.ptr == 0 #make sure that initial value is accessed only once
        INITIAL_MESSAGE = 'INIT20'
        init_tag = self.get_next_tag(INITIAL_MESSAGE)
        return init_tag, INITIAL_MESSAGE

    def evaluate_hash(self, byte_obj):
        return self.hash_function(byte_obj).digest()

    ''' Based on the message to be sent and the current position in 
            the hash chain, return the next tag to use'''

    def get_next_tag(self, message):
        assert not self.is_stale

        chain_tag_bytes = array.array('B', self.chain[self.ptr])
        message_bytes = array.array('B', self.evaluate_hash(message)[0:self.size_tag])

        for i in xrange(self.size_tag): #XOR corresponding bytes
            chain_tag_bytes[i] = chain_tag_bytes[i] ^ message_bytes[i]

        self.ptr += 1
        if self.ptr >= self.chain_length: self.is_stale = True
        return chain_tag_bytes.tostring()

    def __repr__(self):
        return self.chain

    def __str__(self):
        return str(self.chain)

    #Same as evaluate hash before, but doesn't use instance hash function
    @staticmethod
    def evaluate_hash2(byte_obj, hash_func):
        return hash_func(byte_obj).digest()

    '''Reverses get_next_tag. Takes the message tag, and the paired message,
            and determines the original tag in the chain. XORs the message
            with the tag'''
    @staticmethod
    def unwrap_tag(tag, message, hash_func, size_tag):
        chain_tag_bytes = array.array('B', tag)
        message_bytes = array.array('B', HashChain.evaluate_hash2(message, hash_func)[0:size_tag])
        for i in xrange(size_tag):
            chain_tag_bytes[i] = chain_tag_bytes[i] ^ message_bytes[i]
        return chain_tag_bytes.tostring()

    @staticmethod
    def authenticate(prev_tag, prev_message, curr_tag, curr_message, hmac_key, hash_function_str, size_tag):
        if len(prev_tag) != size_tag or len(curr_tag) != size_tag: return False
        hash_function = getattr(hashlib, hash_function_str)
        prev_chain_tag = HashChain.unwrap_tag(prev_tag, prev_message, hash_function, size_tag)
        curr_chain_tag = HashChain.unwrap_tag(curr_tag, curr_message, hash_function, size_tag)
        digest_maker = hmac.new(hmac_key, curr_chain_tag, hash_function)
        correct_tag = digest_maker.digest()[0:size_tag]
        return correct_tag == prev_chain_tag

'''Returns random n-bit number as a string. Useful for HMAC key and chain seed generation.'''
def gen_str_key(n):
    assert n % 8 == 0
    byte_array = [random.getrandbits(8) for i in range(n/8)]
    return str(bytearray(byte_array))

if __name__ == "__main__":
    pass
