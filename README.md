# my-cryptography

This is a simple cryptography library for Python and C.

# One-Time Traceable Ring Signature
## Overview
It is a **C** implementation from [the work of Alessandra Scafuro and Bihan Zhang](https://eprint.iacr.org/2021/1054.pdf) of the Nord Carolina State University. I tried to follow all the points of the paper that I invite you to read.  
I choose to implement this because I believe in post-quantum cryptography and just felt like to implement something for fun. The current state of the work is finished but not polished. Of course I invite you to message me any bugs/problems that for sure a C code has, but don't expect perfection (yet).  
## Performance
All the below informations are calculated assuming a security parameter of 128 bits (16 bytes).  
### Keypair size
| key | size |
|--------------|--------------|
| private_key  |   512bytes   |
| public_key   |   768bytes   |
### Signature size
assuming a message long 32bytes
| ring size | signature size | message | ring size(bytes) |
|---|---|---| --- |
| 2^1 | 544bytes | 32bytes | 1.536Kb | 
| 2^4 | 4.352Kb | 32bytes | 12.288Kb |
| 2^8 | 69.632Kb | 32bytes | 196.608Kb |
| 2^10 | 278.528Kb | 32bytes | 786.432Kb |
| N | N*16^2 + N | msg_size | 3N\*(16)^2


## How to use
See the main function and try to implement it in your code. I will try to make a better documentation in the future.  

## How to compile
Use your own preferred compiler. I prepared a Makefile for gcc so you can just type `make -s` in the terminal. It will create a `main` executable file that you can run to see the result of the main function.  
After that, you can just run with `./main.`  
```
cd one-time-traceable-ring-signature
make -s
./main
``` 


## Possible applications
It can be used for anonymous voting. Each player can make a signature as a group. An outsider seeing the signature cannot know with certainty greater than 1/group_size who in the ring signed the message. Moreover it is Traceable, meaning that if a player inside the ring signs (even the same message!) more than once, this can be traced and the player public key revealed.  
Important note is that with a keypair (public and private keys) it is not suggested(allowed) to sign more than once.  
Possible applications can be online anonymous voting, based on blockchain: a project that I'm working at [github.com/NickP005/e-ring-voting/](https://github.com/NickP005/e-ring-voting/)

## Plans for the future
+ clean the code
+ add more comments, clean comments explaining everything
+ performance tests
+ port to GPU using OpenCL to **G R E A T L Y** improve performance
+ create a python wrapper and then a python package
+ push it to mainstream cryptography libraries
