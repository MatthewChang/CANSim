from hash_encryption import *
CHANNEL_TAG_BYTE_SIZE = 2
HASH_FN = 'sha256'
HMAC_KEY_SIZE = 512
channel_key = gen_str_key(HMAC_KEY_SIZE)
seed = gen_str_key(HMAC_KEY_SIZE)
hash_chain = HashChain(seed, 100, CHANNEL_TAG_BYTE_SIZE,channel_key, HASH_FN)
init_tag,init_message = hash_chain.get_init_tag()
hash_function = getattr(hashlib, HASH_FN)
next_tag = hash_chain.get_next_tag("GOGOGO")
print HashChain.authenticate(init_tag, init_message, next_tag, "GOGOGO", channel_key, HASH_FN, CHANNEL_TAG_BYTE_SIZE)
