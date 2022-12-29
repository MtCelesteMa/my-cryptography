# my-cryptography

This is a simple cryptography library for Python and C.

# One-Time Traceable Ring Signature
## Overview
It is an [implementation from the work](https://eprint.iacr.org/2021/1054.pdf) of Alessandra Scafuro and Bihan Zhang of the Nord Carolina State University. I tried to follow all the points of the paper that I invite you to read.\n
I choose to implement this because I believe in post-quantum cryptography and just felt like to implement something for fun. The current state of the work is finished but not polished. Of course I invite you to message me any bugs/problems that for sure a C code has, but don't expect perfection (yet).
\n
## How to use
See the main function and try to implement it in your code. I will try to make a better documentation in the future.\n

## How to compile
Use your own preferred compiler. I prepared a Makefile for gcc so you can just type `make` in the terminal. It will create a `main` executable file that you can run to see the result of the main function.\n
After that, you can just run with ./main.\n

## Possible applications
It can be used for anonymous voting. Each player can make a signature as a group. An outsider seeing the signature cannot know with certainty greater than 1/group_size who in the ring signed the message. Moreover it is Traceable, meaning that if a player inside the ring signs (even the same message!) more than once, this can be traced and the player public key revealed.\n
Important note is that with a keypair (public and private keys) it is not suggested(allowed) to sign more than once.\n
Possible applications can be online anonymous voting, based on blockchain: a project that I'm working at [github.com/NickP005/e-ring-voting/](https://github.com/NickP005/e-ring-voting/)

## Plans for the future
+ clean the code
+ add more comments, clean comments explaining everything
+ performance tests
+ port to GPU using OpenCL to **G R E A T L Y** improve performance
+ create a python wrapper and then a python package
+ push it to mainstream cryptography libraries