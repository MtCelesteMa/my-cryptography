//https://eprint.iacr.org/2021/1054.pdf

//create the header file for ring.c
#ifndef RING_H
#define RING_H
#include <stdio.h>
#include "sha2.h"

//defined in bytes. Original paper suggests 16 bytes
#define SEC_BYTES 16
//the below values are defined in the paper
//DO NOT CHANGE THEM
#define RING_PKBYTES SEC_BYTES*SEC_BYTES*3
#define RING_SKBYTES (SEC_BYTES*SEC_BYTES*2)

#define RING_GHASH_IN (SEC_BYTES)
#define RING_GHASH_OUT (SEC_BYTES*3)
#define RING_HHASH_IN SEC_BYTES
#define RING_HHASH_OUT SEC_BYTES

//some people will kill me for doing this shortcut
typedef unsigned char u8;

//probably will never used
typedef struct {
    unsigned char pk[RING_PKBYTES];
    unsigned char sk[RING_SKBYTES];
} keypair;

/*
 * Here I could make a structure for each
 * member inside a signature. But I think
 * that would waste computation energy in
 * some parts of the code.
 */

/* This will help understanding:
 * HHash(). IN: SEC_BYTES. OUT: SEC_BYTES
 * GHash(). IN: SEC_BYTES. OUT: SEC_BYTES*3 
 */

/* SIGNATURES OF RING.C */
void keygen(u8 *pk, u8 *sk);
void RSign(u8 *sigout ,u8 *pks, unsigned int N, u8 *sk, unsigned int pos, u8 *msg, unsigned int msg_len);
int RVer(u8 *pks, unsigned int N, u8 *msg, unsigned int msg_len, u8 *sigs);
int RTrace(u8 *pks, unsigned int N, u8 *sig1, u8 *sig2, u8 **point);


#endif /* RING_H */