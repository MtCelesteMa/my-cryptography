# crypto-otrs: One-time Traceable Ring Signature
```
pip3 install crypto-otrs
```


Based on the [the work of Alessandra Scafuro and Bihan Zhang](https://eprint.iacr.org/2021/1054.pdf) of the Nord Carolina State University.  
Use this at your own risk. This is a python library that wraps the C code you can find at my github [github.com/NickP005/my-cryptography](https://github.com/NickP005/my-cryptography). 
Quantum-resistant, speedy, black-box, random oracle

## What is a ring signature
A ring signature is a cryptographic signature scheme that can be signed by any member of a group of users (AKA "ring"). The signer produces a signature on the message that proves the message has been signed by one of the group members, but it is impossible to know certainly who.
    
For example: during the meeting of Pear's shareholders (Luca, Matteo and Lucia), each shareholder is asked to vote anonymously on the increase in payrool of the employees. Looking just to Luca (but the other members will do the same): Luca generates a keypair and publishes it to the world. Then, after Luca gets Matteo and Lucia's ones, he makes signs the message "I approve to increase payrool at date XX/XX/XXXX" on behalf of the ring of public keys (Luca, Matteo, Lucia). Then they anonymously submit the signatures to a notary that looking at the signature, cannot deduce anything except that the signer could be with equal probability Luca as well as Matteo as well as Lucia.  
This scheme is traceable in the sense that if Matteo wanted to cheat (give more weight to his opinion) and signs 2 messages, the notary will be able to trace back, given the 2 messages, to Matteo's public key.

Pay attention that the public/private keypair is throwaway and **must be used once** (recall: one time). Only one message is signable at time.

## How to use
Below some example usage

### Create a keypair
```
from crypto_otrs import ring

public_key, private_key = ring.keygen()
```

### Sign a message
```
from crypto_otrs import ring

bob_public, bob_private = ring.keygen()
alice_public, alice_private = ring.keygen()

ring = []
ring.append(bob_public)
ring.append(alice_public)

# here Alice signs pasta vs pizza feud
# position of Alice's public key is 1
alice_signature = ring.RSign(ring, alice_private, 1, b"pizza is the besta food of the world")
```

### Verify a signature
now someone gets a "signature", the public keys (MUST BE IN ORDER!) of it and the message:
```
from crypto_otrs import ring

is_valid = ring.RVer(ring, b"pizza is the besta food of the world", signature) 
# --> True or False
```

### Trace a signature
We don't know if Bob voted yet or is still playing video games, but we got 2 signatures... let's check if Alice cheated (Alice likes to cheat often):
```
from crypto_otrs import ring

is_from_same_signer, traced_public_key = ring.RTrace(ring, signature_1, signature_2)
# --> True, alice_public
# ...Alice cheated
```

## Technical overview
### keygen() 
`public_key[768], private_key[512] = ring.keygen()`  
returns a public/private keypair tuple stored in the form of uint_8 arrays.
### RSign() 
`signature[SIG_LEN] = ring.RSign(ring, private_key, position, message)`  
where `SIG_LEN = N*256 + N*16`  
generates a signature in the form of a uint_8 array. Takes in the array of public keys of the ring, the private key, the position of the public key in the ring (start from 0) and a message that should be in the form of bytes.
### RVer() 
`is_valid = RVer(ring, message, signature)`  
outputs `True` when the signature is valid, `False` otherwise.  
Takes in the array of public keys (ring), the message (as said before, in bytes) and the signature.
### RTrace() 
`traces, traced = RTrace(ring, signature_1, signature_2)`  
outputs a tuple where the first element is a boolean that outputs `True` when the two signatures came from the same private key. In this case the `traced` variable is equal to the public key of the traced signature.

## Performance
I didn't test python ones, since it is a wrapper, should be te same as [github.com/NickP005/my-cryptography](https://github.com/NickP005/my-cryptography)