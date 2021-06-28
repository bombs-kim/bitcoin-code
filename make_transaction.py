import key_utils
import txn_utils


privateKey = key_utils.wif_to_private_key(
    "5HusYj2b2x4nroApgfvaSfKYZhRbKFH41bVyPooymbC6KfgSXdD") #1MMMM

signed_txn = txn_utils.make_signed_transaction(
    privateKey,
    "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48", # output (prev) transaction hash
    0, # sourceIndex
    key_utils.addr_hash_to_script_pub_key("1MMMMSUb1piy2ufrSguNUdFmAcvqrQF8M5"),
    [
        [91234, #satoshis
        key_utils.addr_hash_to_script_pub_key("1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa")]])

txn_utils.verify_txn_signature(signed_txn)
print('SIGNED TXN', signed_txn)
