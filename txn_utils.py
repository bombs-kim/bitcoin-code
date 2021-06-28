# https://pypi.python.org/pypi/ecdsa/0.10

import ecdsa
import hashlib
import struct
import unittest

import utils
import key_utils


def _make_output(data):
    redemption_satoshis, output_script = data
    return (struct.pack("<Q", redemption_satoshis).encode('hex') +
        '%02x' % len(output_script.decode('hex')) + output_script)

# Makes a transaction from the inputs
# outputs is a list of [redemptionSatoshis, outputScript]
def make_raw_transaction(
    output_transaction_hash, sourceIndex, script_sig, outputs):
    formattedOutputs = ''.join(map(_make_output, outputs))
    return (
        "01000000" +    # 4 bytes version
        "01" +          # varint for number of inputs
        output_transaction_hash.decode('hex')[::-1].encode('hex') + # reversed
        struct.pack('<L', sourceIndex).encode('hex') +
        '%02x' % len(script_sig.decode('hex')) + script_sig +
        "ffffffff" +            # sequence
        "%02x" % len(outputs) + # number of outputs
        formattedOutputs +
        "00000000"              # lockTime
        )

# Returns [first, sig, pub, rest]
def parse_txn(txn):
    first = txn[0:41*2]
    scriptLen = int(txn[41*2:42*2], 16)
    script = txn[42*2:42*2+2*scriptLen]
    sigLen = int(script[0:2], 16)
    sig = script[2:2+sigLen*2]
    pubLen = int(script[2+sigLen*2:2+sigLen*2+2], 16)
    pub = script[2+sigLen*2+2:]

    assert(len(pub) == pubLen*2)
    rest = txn[42*2+2*scriptLen:]
    return [first, sig, pub, rest]

# Substitutes the scriptPubKey into the transaction, appends SIGN_ALL to make the version
# of the transaction that can be signed
def get_signable_txn(parsed):
    first, sig, pub, rest = parsed
    inputAddr = utils.base58check_decode(key_utils.pub_key_to_addr(pub))
    return first + "1976a914" + inputAddr.encode('hex') + "88ac" + rest + "01000000"

# Verifies that a transaction is properly signed, assuming the generated scriptPubKey matches
# the one in the previous transaction's output
def verify_txn_signature(txn):
    parsed = parse_txn(txn)
    signable_txn = get_signable_txn(parsed)
    hash_to_sign = hashlib.sha256(hashlib.sha256(signable_txn.decode('hex')).digest()).digest().encode('hex')
    assert(parsed[1][-2:] == '01') # hashtype
    sig = key_utils.der_sig_to_hex_sig(parsed[1][:-2])
    public_key = parsed[2]
    vk = ecdsa.VerifyingKey.from_string(public_key[2:].decode('hex'), curve=ecdsa.SECP256k1)
    assert(vk.verify_digest(sig.decode('hex'), hash_to_sign.decode('hex')))


def make_signed_transaction(
    private_key, output_transaction_hash, source_index, script_pub_key, outputs):
    myTxn_forSig = (
        make_raw_transaction(
            output_transaction_hash, source_index, script_pub_key, outputs)
         + "01000000") # hash code

    s256 = hashlib.sha256(
        hashlib.sha256(myTxn_forSig.decode('hex')).digest()).digest()
    sk = ecdsa.SigningKey.from_string(
        private_key.decode('hex'), curve=ecdsa.SECP256k1)
    sig = sk.sign_digest(s256, sigencode=ecdsa.util.sigencode_der) + '\01' # 01 is hashtype
    pubKey = key_utils.private_key_to_public_key(private_key)
    script_sig = utils.varstr(sig).encode('hex') + utils.varstr(pubKey.decode('hex')).encode('hex')
    signed_txn = make_raw_transaction(
        output_transaction_hash, source_index, script_sig, outputs)
    verify_txn_signature(signed_txn)
    return signed_txn


class TestTxnUtils(unittest.TestCase):
    def test_verify_parse_txn(self):
        txn = (
            "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000"
            "8a47"
            "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01"
            "41"
            "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55"
            "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000"
            "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000")

        parsed = parse_txn(txn)
        self.assertEqual(parsed[0], "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000")
        self.assertEqual(parsed[1], "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01")
        self.assertEqual(parsed[2], "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55")
        self.assertEqual(parsed[3], "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
                        "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000")

    def test_verify_signable_txn(self):
        txn = (
            "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000"
            "8a47"
            "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01"
            "41"
            "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55"
            "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000"
            "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000")

        parsed = parse_txn(txn)
        my_txn_for_sig = (
            "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000"
            "1976a914"  "167c74f7491fe552ce9e1912810a984355b8ee07"  "88ac"
            "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000"
            "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000"
            "01000000")
        signable_txn = get_signable_txn(parsed)
        self.assertEqual(signable_txn, my_txn_for_sig)

    def test_verifyTxn(self):
        txn = (
            "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000"
            "8a47"
            "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01"
            "41"
            "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55"
            "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000"
            "1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000")
        verify_txn_signature(txn)

    def test_make_raw_transaction(self):
        #http://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
        txn = make_raw_transaction(
            "f2b3eb2deb76566e7324307cd47c35eeb88413f971d88519859b1834307ecfec", # output transaction hash
            1,              # sourceIndex
            "76a914010966776006953d5567439e5e39f86a0d273bee88ac", # scriptSig
            [
                [99900000,  #satoshis
                "76a914097072524438d003d23a2f23edb65aae1bb3e46988ac"]], # outputScript
            ) + "01000000"  # hash code type
        self.assertEqual(
            txn,
            "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2" +
            "010000001976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff" +
            "01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac" +
            "0000000001000000")

    def test_make_signed_transaction(self):
        # Transaction from
        # https://blockchain.info/tx/901a53e7a3ca96ed0b733c0233aad15f11b0c9e436294aa30c367bf06c3b7be8
        # From 133t to 1KKKK
        private_key = key_utils.wif_to_private_key(
            "5Kb6aGpijtrb8X28GzmWtbcGZCG8jHQWFJcWugqo3MwKRvC8zyu") #133t

        signed_txn = make_signed_transaction(
            private_key,
            "c39e394d41e6be2ea58c2d3a78b8c644db34aeff865215c633fe6937933078a9", # output (prev) transaction hash
            0, # sourceIndex
            key_utils.addr_hash_to_script_pub_key("133txdxQmwECTmXqAr9RWNHnzQ175jGb7e"),
            [
                [24321, #satoshis
                key_utils.addr_hash_to_script_pub_key("1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa")],
                [20000, key_utils.addr_hash_to_script_pub_key("15nhZbXnLMknZACbb3Jrf1wPCD9DWAcqd7")]])

        verify_txn_signature(signed_txn)

if __name__ == '__main__':
    unittest.main()
