"""SHA-256, HMAC-SHA256 e PBKDF2-HMAC-SHA256 implementados manualmente.
Somente operações de bytes/inteiros da linguagem, sem hashlib/hmac/bibliotecas criptográficas.
Para fins acadêmicos: Python puro é significativamente mais lento que implementações nativas.
"""
import secrets

MASK = 0xffffffff
K = (
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2)
INIT=(0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)

def rotr(v, n): return (v>>n | v<<(32-n)) & MASK

def sha256(data):
    data=bytes(data)
    length=len(data)*8
    padded=data+b'\x80'+b'\x00'*((55-len(data))%64)+length.to_bytes(8,'big')
    h=list(INIT)
    for off in range(0,len(padded),64):
        b=padded[off:off+64]
        w=[int.from_bytes(b[i:i+4],'big') for i in range(0,64,4)]
        for i in range(16,64):
            x,y=w[i-15],w[i-2]
            s0=rotr(x,7)^rotr(x,18)^(x>>3)
            s1=rotr(y,17)^rotr(y,19)^(y>>10)
            w.append((w[i-16]+s0+w[i-7]+s1)&MASK)
        a,c,d,e,f,g,j,k=h
        for i in range(64):
            s1=rotr(f,6)^rotr(f,11)^rotr(f,25)
            ch=(f & g) ^ (~f & j)
            t1=(k+s1+ch+K[i]+w[i])&MASK
            s0=rotr(a,2)^rotr(a,13)^rotr(a,22)
            maj=(a & c)^(a & d)^(c & d)
            t2=(s0+maj)&MASK
            a,c,d,e,f,g,j,k=(t1+t2)&MASK,a,c,d,(e+t1)&MASK,f,g,j
        h=[(v+u)&MASK for v,u in zip(h,(a,c,d,e,f,g,j,k))]
    return b''.join(v.to_bytes(4,'big') for v in h)

def hmac_sha256(key,data):
    key=bytes(key);data=bytes(data)
    if len(key)>64: key=sha256(key)
    key=key.ljust(64,b'\x00')
    inner=bytes(c^0x36 for c in key)
    outer=bytes(c^0x5c for c in key)
    return sha256(outer+sha256(inner+data))

def pbkdf2_sha256(password,salt,iterations,dklen=32):
    if not isinstance(iterations,int) or not 1<=iterations<=10_000_000: raise ValueError('iterações inválidas')
    if not 1<=dklen<=1024: raise ValueError('tamanho inválido')
    out=bytearray()
    for counter in range(1,(dklen+31)//32+1):
        u=hmac_sha256(password,salt+counter.to_bytes(4,'big'))
        acc=bytearray(u)
        for _ in range(1,iterations):
            u=hmac_sha256(password,u)
            for j in range(32): acc[j]^=u[j]
        out.extend(acc)
    return bytes(out[:dklen])

def compare_digest(a,b):
    if not isinstance(a,type(b)) or not isinstance(a,(str,bytes)): return False
    a=a.encode('utf-8') if isinstance(a,str) else a
    b=b.encode('utf-8') if isinstance(b,str) else b
    mismatch=len(a)^len(b)
    for x,y in zip(a,b): mismatch|=x^y
    return mismatch==0
