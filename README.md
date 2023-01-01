# my-cryptography

This is a simple cryptography library for Python and C.

# One-Time Traceable Ring Signature
## Table of contents
* [Overview](#overview)
* [Performance](#performance)
* [How to compile](#how-to-compile)
* [Possible applications](#possible-applications)
* [Plans for the future](#plans-for-the-future)

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
### Tests conducted
| test type | sample size | milliseconds | ms each |
|---|---|---|---|
| keypair generation | 10000 | 872.726ms | 0.0872ms | 
|sign N=2| 1000 | 151.348000ms | 0.151348ms |
|sign N=16| 1000 | 1112.777000ms | 1.112777ms |
|sign N=32| 1000 | 2189.722000ms | 2.189722ms |
|sign N=64| 1000 | 4298.431000ms | 4.298431ms |
|sign N=128| 1000 | 8683.565000ms | 8.683565ms |
|sign N=256| 1000 | 17377.749000ms | 17.377749ms |
|sign N=512| 100 | 3509.350000ms | 35.093500ms |
|sign N=1024| 100 | 6935.590000ms | 69.355900ms |
|sign&ver N=2| 1000 | 328.129000ms | 0.328129ms |
|sign&ver N=16| 1000 | 2267.926000ms | 2.267926ms |
|sign&ver N=32| 1000 | 4331.254000ms | 4.331254ms |
|sign&ver N=64| 1000 | 8863.452000ms | 8.863452ms |
|sign&ver N=128| 1000 | 17518.844000ms | 17.518844ms |
|sign&ver N=256| 1000 | 35187.886000ms | 35.187886ms |
|sign&ver N=512| 100 | 7205.680000ms | 72.056800ms |
|sign&ver N=1024| 100 | 14689.807000ms | 146.898070ms |
|verify N=2| 1000 | 151.614000ms | 0.151614ms |
|verify N=16| 1000 | 1116.654000ms | 1.116654ms |
|verify N=32| 1000 | 2190.187000ms | 2.190187ms |
|verify N=64| 1000 | 4331.969000ms | 4.331969ms |
|verify N=128| 1000 | 8687.751000ms | 8.687751ms |
|verify N=256| 1000 | 17353.195000ms | 17.353195ms |
|verify N=512| 100 | 3496.695000ms | 34.966950ms |
|verify N=1024| 100 | 7306.840000ms | 73.068400ms |

Trace benchmark will be made later when the optimised RTraces() function is completed. Sorry for the disorder of `main.c`, but you will find a good documented `ring.c` and `ring.h`.

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
Important note: a key must be used only once and then canceled. If the key is reused (for even the same signature), no security guarantee is provided in terms of anonymity and unforgeability.  
Possible applications can be online anonymous voting, based on blockchain: a project that I'm working at [github.com/NickP005/e-ring-voting/](https://github.com/NickP005/e-ring-voting/)

## Plans for the future
+ clean the code
+ add more comments, clean comments explaining everything
+ performance tests
+ port to GPU using OpenCL to **G R E A T L Y** improve performance
+ create a python wrapper and then a python package
+ push it to mainstream cryptography libraries
