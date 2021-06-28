import random, key_utils

private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
print(key_utils.private_key_to_public_key(private_key))
print(key_utils.key_to_addr(private_key))
