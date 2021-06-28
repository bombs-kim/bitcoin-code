import hashlib
import struct
import unittest


b58 = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


# Returns byte string value, not hex string
def varint(n):
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n < 0xffff:
        return struct.pack('<cH', '\xfd', n)
    elif n < 0xffffffff:
        return struct.pack('<cL', '\xfe', n)
    else:
        return struct.pack('<cQ', '\xff', n)


# Takes and returns byte string value, not hex string
def varstr(s):
    return varint(len(s)) + s


# 60002
def netaddr(ipaddr, port):
    services = 1
    return (struct.pack('<Q12s', services, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff') +
                       struct.pack('>4sH', ipaddr, port))


# return value, len
def processVarInt(payload):
    n0 = ord(payload[0])
    if n0 < 0xfd:
        return [n0, 1]
    elif n0 == 0xfd:
        return [struct.unpack('<H', payload[1:3])[0], 3]
    elif n0 == 0xfe:
        return [struct.unpack('<L', payload[1:5])[0], 5]
    else:
        return [struct.unpack('<Q', payload[1:5])[0], 7]


# return value, len
def processVarStr(payload):
    n, length = processVarInt(payload)
    return [payload[length:length+n], length + n]


# takes 26 byte input, returns string
def processAddr(payload):
    assert(len(payload) >= 26)
    return '%d.%d.%d.%d:%d' % (ord(payload[20]), ord(payload[21]),
                               ord(payload[22]), ord(payload[23]),
                               struct.unpack('!H', payload[24:26])[0])


def base58_encode(n: int) -> bytes:
    result = []
    while n > 0:
        result.append(b58[n%58])
        n //= 58
    return bytes(reversed(result))


def base58_decode(s: bytes):
    result = 0
    for b in s:
        result = result * 58 + b58.index(b)
    return result


def base256_encode(n: int) -> bytes:
    result = []
    while n > 0:
        result.append(n % 256)
        n //= 256
    return bytes(reversed(result))


def base256_decode(s: bytes) -> int:
    result = 0
    for c in s:
        result = result * 256 + c
    return result


def count_leading_chars(s: bytes, ch: int):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count


# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58check_encode(version: int, payload: bytes) -> bytes:
    s = bytes([version]) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    leading_zeros = count_leading_chars(result, ord('\0'))
    result = base58_encode(base256_decode(result))
    return b'1' * leading_zeros + result


def base58check_decode(s:bytes) -> bytes:
    leading_ones = count_leading_chars(s, ord('1'))
    s = base256_encode(base58_decode(s))
    result = bytes([b'\0'] * leading_ones) + s[:-4]
    chk = s[-4:]
    checksum = hashlib.sha256(hashlib.sha256(result).digest()).digest()[0:4]
    assert(chk == checksum)
    # version = result[0]
    return result[1:]


class TestUtils(unittest.TestCase):
    def test_varint(self):
        self.assertEqual(varint(0x42), '\x42')
        self.assertEqual(varint(0x123), '\xfd\x23\x01')
        self.assertEqual(varint(0x12345678), '\xfe\x78\x56\x34\x12')
        self.assertEqual(processVarInt(varint(0x42)), [0x42, 1])
        self.assertEqual(processVarInt(varint(0x1234)), [0x1234, 3])

    def test_varstr(self):
        self.assertEqual(varstr('abc'), '\x03abc')
        self.assertEqual(processVarStr('\x03abc'), ['abc', 4])

    def test_processAddr(self):
        self.assertEqual(processAddr('x'*20 + '\x62\x91\x98\x16\x20\x8d'),
                         '98.145.152.22:8333')

    def test_countLeadingCharacters(self):
        self.assertEqual(count_leading_chars('a\0bcd\0', '\0'), 0)
        self.assertEqual(count_leading_chars('\0\0a\0bcd\0', '\0'), 2)
        self.assertEqual(count_leading_chars('1a\0bcd\0', '1'), 1)

    def test_base256(self):
        self.assertEqual(base256_encode(base256_decode('abc')), 'abc')
        self.assertEqual(base256_encode(0x4142), 'AB')
        self.assertEqual(base256_decode('AB'), 0x4142)

    def test_base58(self):
        self.assertEqual(base58_encode(base58_decode('abc')), 'abc')
        self.assertEqual(base58_decode('121'), 58)
        self.assertEqual(base58_decode('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'),
            0x800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D)

    def test_base58check(self):
        self.assertEqual(base58check_decode(base58check_encode(42, 'abc')), 'abc')
        self.assertEqual(base58check_decode(base58check_encode(0, '\0\0abc')), '\0\0abc')
        s = base256_encode(0x0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D)
        b = base58check_encode(0x80, s)
        self.assertEqual(b, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")


if __name__ == '__main__':
    unittest.main()
