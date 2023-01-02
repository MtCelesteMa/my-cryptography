#clang -fPIC -shared -g -lm -lssl -lcrypto ring.c sha2.c -o libring.so
"""
AIM OF THIS CODE: be the safest one, think that the end user
is a noob and is idiot, so check everything, even if it's
not necessary, and make it as simple as possible.
"""
import os
from ctypes import *

script_dir = os.path.abspath(os.path.dirname(__file__))
lib_path = os.path.join(script_dir, "libring.so")

# import shared lib
libring = cdll.LoadLibrary(lib_path)

# define argument types for the add_fifthy function from the shared lib
libring.keygen.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
libring.RSign.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte),
c_uint, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), c_uint]
libring.RVer.argtypes = [POINTER(c_ubyte), c_uint, 
POINTER(c_ubyte), c_uint, POINTER(c_ubyte)]
libring.RTrace.argtypes = [POINTER(c_ubyte), c_uint, 
POINTER(c_ubyte), POINTER(c_ubyte), POINTER(POINTER(c_ubyte))]

def keygen():
    # allocates memory for an equivalent array in C and populates it with
    # values from `arr`
    pk = (c_ubyte * (768))(*[])
    sk = (c_ubyte * (512))(*[])

    # Call the C function
    libring.keygen(pk, sk)

    return pk[:], sk[:]
    
# ring: ring of public keys (pk1[], pk2[], ..., pkn[])
def RSign(ring, sk, pos, msg):
    #since python is for noobs, lets do some check every
    #good programmer should have done
    if(pos < 0 or pos >= len(ring)):
        raise Exception("Invalid position")
    if(len(msg) == 0):
        raise Exception("Invalid message")
    if(len(ring) < 2):
        raise Exception("Invalid ring lenght")
    if(len(sk) != 512):
        raise Exception("Invalid secret key lenght")
    N = len(ring)
    pks = []
    for i in range(N):
        if(len(ring[i]) != 768):
            raise Exception("Invalid public key lenght at position " + str(i))
        pks += ring[i]
    pks = (c_ubyte * (768*N))(*pks)
    N_c = c_uint(N)
    sk = (c_ubyte * (512))(*sk)
    pos_c = c_uint(pos)
    #if msg is not a byte array, convert it
    #even if I strongly suggest to use byte arrays
    if(type(msg) != bytes):
        msg = str(msg).encode()
    msg_c = (c_ubyte * (len(msg)))(*msg)
    msg_len = c_uint(len(msg))
    sig = (c_ubyte * (N*16+N*16*16))(*[])
    libring.RSign(sig, pks, N_c, sk, pos_c, msg_c, msg_len)
    
    return sig[:]

def RVer(ring, msg, sig):
    if(len(msg) == 0):
        raise Exception("Invalid message")
    if(len(ring) < 2):
        raise Exception("Invalid ring lenght")
    N = len(ring)
    pks = []
    for i in range(N):
        if(len(ring[i]) != 768):
            raise Exception("Invalid public key lenght at position " + str(i))
        pks += ring[i]
    pks = (c_ubyte * (768*N))(*pks)
    N_c = c_uint(N)
    #if msg is not a byte array, convert it
    #even if I strongly suggest to use byte arrays
    if(type(msg) != bytes):
        msg = str(msg).encode()
    msg_c = (c_ubyte * (len(msg)))(*msg)
    msg_len = c_uint(len(msg))
    sig = (c_ubyte * (N*16+N*16*16))(*sig)
    res = libring.RVer(pks, N_c, msg_c, msg_len, sig)
    if(res == 1):
        return True
    else:
        return False

def RTrace(ring, sig1, sig2):
    if(len(ring) < 2):
        raise Exception("Invalid ring lenght")
    N = len(ring)
    pks = []
    for i in range(N):
        if(len(ring[i]) != 768):
            raise Exception("Invalid public key lenght at position " + str(i))
        pks += ring[i]
    pks = (c_ubyte * (768*N))(*pks)
    N_c = c_uint(N)
    sig1 = (c_ubyte * (N*16+N*16*16))(*sig1)
    sig2 = (c_ubyte * (N*16+N*16*16))(*sig2)
    trace = POINTER(c_ubyte)()
    res = libring.RTrace(pks, N_c, sig1, sig2, trace)
    if(res == 1):
        return True, trace[:768]
    else:
        return False, []

if __name__ == "__main__":
    pk, sk = keygen()
    pk2, sk2 = keygen()
    ring = [pk, pk2]
    sig = RSign(ring, sk, 0, "ciao")
    sig2 = RSign(ring, sk, 0, "ciao")

    is_valid = RVer(ring, "ciao", sig)

    traced, trace = RTrace(ring, sig, sig2)
    #print("Traced: " + str(traced))
    #print("Trace: " + str(trace))
    #print(pk)
    if(pk == trace):
        print("Trace is correct")
