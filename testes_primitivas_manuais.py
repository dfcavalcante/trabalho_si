from primitivas_manuais import sha256,hmac_sha256,pbkdf2_sha256,compare_digest
assert sha256(b'').hex()=='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
assert sha256(b'abc').hex()=='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
assert hmac_sha256(b'key',b'The quick brown fox jumps over the lazy dog').hex()=='f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8'
assert pbkdf2_sha256(b'password',b'salt',1).hex()=='120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
assert compare_digest('same','same') and not compare_digest('same','else')
print('OK: SHA-256, HMAC, PBKDF2 manuais — vetores conhecidos')
