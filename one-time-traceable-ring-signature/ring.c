//https://eprint.iacr.org/2021/1054.pdf

#include "ring.h"

/*
 * this function checks if two arrays of the same
 * length are equal.
 * Note: the fact that returns as soon as it finds out
 * there is no identity, is not a vulnerability.
 */
int check_identity(u8 *arr1, u8 *arr2, int len) {
  for(int i =0; i<len; i++) {
    if(arr1[i] != arr2[i]) {
      return 0;
    }
  }
  return 1;
}

/*
 * test_uniqness takes in an array[count] of arrays[size]
 * clearly: [[A,B,C], [C,D,E]] -> count = 2, size = 3
 * it checks if there is even one duplicate in the array
 */
int test_uniqness(u8 *arr, int size, int count) {
  for(int i=0; i<count-1; i++) {
    for(int j=i+1; j<count; j++) {
      if(check_identity(arr+i*size, arr+j*size, size)) {
        return 0;
      }
    }
  }
  return 1;
}

void print_array(u8 *array, int len) {
  printf("[");
  for(int loop = 0; loop < len-1; loop++)
      printf("%d, ", array[loop]);
  printf("%d", array[len-1]);
  printf("]\n");
}

/*
 * GHash is defined as a black box modeles as a random oracle 
 * that takes in a seed of SEC_BYTES length and 
 * outputs a SEC_BYTES*3 length array.
 */
void GHash(u8 *input, u8 *output) {
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, input, SEC_BYTES);
  u8 hashout[32];
  for(int used_bytes = 0; used_bytes<SEC_BYTES*3; used_bytes++) {
    int relative = used_bytes % 32;
    if(relative == 0) {
      sha256_update(&ctx, (u8 []){0}, 1);
      sha256_final(&ctx, hashout);
    }
    output[used_bytes] = hashout[relative];
        //output[used_bytes] = 3; //testing
  }
}

/*
 * HHash is defined as a black box modeles as a random oracle
 * that takes in a seed of  input_len bytes and 
 * outputs a SEC_BYTES*3 bytes array.
 */
void HHash(u8 *input, unsigned int input_len, u8 *output) {
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, input, input_len);
  u8 hashout[32];
  for(int used_bytes = 0; used_bytes<SEC_BYTES; used_bytes++) {
    int relative = used_bytes % 32;
    if(relative == 0) {
      sha256_update(&ctx, (u8 []){1}, 1);
      sha256_final(&ctx, hashout);
    }
    output[used_bytes] = hashout[relative];
  }
}

/*
  * keygen outputs on the two pointers pk and sk:
  * pk[RING_PKBYTES] -> the public key
  * sk[RING_SKBYTES] -> the secret key
  */
void keygen(u8 *pk, u8 *sk) {
  //generate the 2 secret seeds at the same time
  RAND_priv_bytes(sk, RING_SKBYTES);
  u8 g_1[RING_PKBYTES], g_2[RING_PKBYTES];
  for(int i=0; i<SEC_BYTES; i++) {
    GHash(sk+i*RING_GHASH_IN, g_1+i*RING_GHASH_OUT);
    GHash(sk+SEC_BYTES*RING_GHASH_IN+i*RING_GHASH_IN, 
          g_2+i*RING_GHASH_OUT);
  }
  for(int i=0; i<RING_PKBYTES; i++) {
    pk[i] = g_1[i] ^ g_2[i];
  }
}

/*
 * RSign takes in the following parameters:
 * sigout[N*SEC_BYTES + N*SEC_BYTES*SEC_BYTES] --> signature where
 *  the first N*SEC_BYTES are the commitments(z) and the rest is the
 *  challenge (r).
 * pks[N*RING_PKBYTES] --> the public keys of the ring
 * N --> the number of public keys
 * sk[RING_SKBYTES] --> the secret key
 * pos --> the position of the signer in the ring
 * msg[msg_len] --> the message to be signed  
 * msg_len --> the length of the message to be signed
 */
void RSign(u8 *sigout, u8 *pks, unsigned int N, u8 *sk, unsigned int pos, u8 *msg, unsigned int msg_len) {
  
  u8 c[N*SEC_BYTES*SEC_BYTES*3];
  //random strings to commit to
  u8 z[N*SEC_BYTES];
  RAND_bytes(z, N*SEC_BYTES);
  //fictional seeds
  u8 r[N*SEC_BYTES*SEC_BYTES];
  RAND_bytes(r, N*SEC_BYTES*SEC_BYTES);
  // for each member of the ring, generate the challenge(r) with the
  // commitment(z) and the public key
  for(unsigned int l=0; l < N; l++ ) {
    if(l == pos) {
      //reset the commitment z to 0 to don't influence the target proof
      //this exact position will be set later. Repeat SEC_BYTES times..
      for(int i=pos*SEC_BYTES; i < pos*SEC_BYTES + SEC_BYTES; i++) {
        z[i] = 0;
      }
      for(int i=0; i<SEC_BYTES; i++) {
        int c_pos = pos*SEC_BYTES*SEC_BYTES*3 + i*SEC_BYTES*3;
        GHash(sk+SEC_BYTES*i, c+c_pos);
      }
    } else {
      /*
       * now prove the commitment (z) with the challenge (r):
       * if z is 0, just GHash the challenge (r) as the commitment
       * if z is 1, GHash the challenge (r) and XOR with the
       * corresponding public key.
       */ 
      for(int i=0; i<SEC_BYTES; i++) {
        int c_pos = l*SEC_BYTES*SEC_BYTES*3 + i*SEC_BYTES*3;
        int r_pos = l*SEC_BYTES*SEC_BYTES + i*SEC_BYTES;
        GHash(r+r_pos, c+c_pos);
        if(z[l*SEC_BYTES+i]%2) {
          for(int e=c_pos; e<c_pos+SEC_BYTES*3; e++) {
            c[e] ^= pks[e];
          }
        }
      }
    }
  }
  //now compute the target  with H(pks ring, msg, commitments(c))
  int hashing_len = (N*SEC_BYTES*SEC_BYTES*3) + msg_len + (N*SEC_BYTES*SEC_BYTES*3);
  u8 hashing_pot[hashing_len];
  for(int i=0; i<(N*SEC_BYTES*SEC_BYTES*3); i++) {
    hashing_pot[i] = pks[i];
  }
  for(int i=0, j=(N*SEC_BYTES*SEC_BYTES*3); i<msg_len; i++, j++) {
    hashing_pot[j] = msg[i];
  }
  for(int i=0, j=(N*SEC_BYTES*SEC_BYTES*3)+msg_len; i<(N*SEC_BYTES*SEC_BYTES*3); i++, j++) {
    hashing_pot[j] = c[i];
  }
  u8 target[SEC_BYTES]; //RING_HHASH_OUT
  HHash(hashing_pot, hashing_len, target);
  /*
   * now set the random string (z) that our PK will commit to
   * in a way so that the XOR of the commitments (z) is equal
   * to the target.
   * clearly: target = XOR(z1, z2, ..., zl, ..., zN)
   */
  for(int i=0; i<SEC_BYTES; i++) {
    z[pos*SEC_BYTES+i] = target[i];
  }
  for(int l=0; l<N; l++) {
    if(l==pos) {
      continue;
    }
    //I don't know if this particular nested loop is efficient
    for(int i=0; i<SEC_BYTES; i++) {
      z[pos*SEC_BYTES+i] ^= z[l*SEC_BYTES+i];
    }
  }

  //now compute the challenge(r) corresponding to our PK now that
  //we have the commitment (z) to commit to.
  for(int i=0; i<SEC_BYTES; i++) {
    int pseudo_zbit = z[pos*SEC_BYTES+i]%2;
    //keeps in count which seed of the two of the private key to use
    //namely g_1 or g_2
    int base_seedlocation = pseudo_zbit*SEC_BYTES*SEC_BYTES+i*SEC_BYTES;
    int base_rseed = pos*SEC_BYTES*SEC_BYTES+i*SEC_BYTES;
    //copy the private key seed to the challenge
    for(int j=0; j<SEC_BYTES; j++) {
      r[base_rseed+j] = sk[base_seedlocation+j];
    }
  }
  /*
   * The full signature would be {pks, z, r, msg, msg_len} but
   * the only real information we processed here is z and r.
   * sigout is the concatenation of z(commitments)[N*SEC_BYTES] 
   * and r[N*SEC_BYTES*SEC_BYTES](challenges). 
   * clearly: sigout[N*SEC_BYTES + N*SEC_BYTES*SEC_BYTES]
   */
  for(int i=0; i<N*SEC_BYTES; i++) {
    sigout[i] = z[i];
  }
  for(int i=0, j=(N*SEC_BYTES); i<N*SEC_BYTES*SEC_BYTES; i++, j++) {
    sigout[j] = r[i];
  }
}

/*
 * RVer outputs 1 if the signature(ring, sigs, msg) is valid, 0 otherwise.
 * pks[N*RING_PKBYTES]: public keys
 * N: number of public keys
 * msg: msg that was used to sign
 * msg_len: its lenght
 * sigs{z[N*SEC_BYTES], r[N*SEC_BYTES*SEC_BYTES]}: the signatures
 */
int RVer(u8 *pks, unsigned int N, u8 *msg, unsigned int msg_len, u8 *sigs) {
  //check all keys are distinct
  if(!test_uniqness(pks, RING_PKBYTES, N)) {
    #ifdef DEBUG
    printf("RVer(): the keys are not distict!");
    #endif
    return 0;
  }
  u8 c[N*SEC_BYTES*SEC_BYTES*3];
  u8 *z = sigs;
  u8 *r = sigs+N*SEC_BYTES;
  //compute the commitments
  for(int l=0; l<N; l++) {
    for(int i=0; i<SEC_BYTES; i++) {
      int c_pos = l*SEC_BYTES*SEC_BYTES*3 + i*SEC_BYTES*3;
      int r_pos = l*SEC_BYTES*SEC_BYTES + i*SEC_BYTES;
      GHash(r+r_pos, c+c_pos);
      if(sigs[l*SEC_BYTES+i]%2) {
        for(int e=c_pos; e<c_pos+SEC_BYTES*3; e++) {
            c[e] ^= pks[e];
          }
      }
    }
  }
  int hashing_len = (N*SEC_BYTES*SEC_BYTES*3) + msg_len + (N*SEC_BYTES*SEC_BYTES*3);
  u8 hashing_pot[hashing_len];
  for(int i=0; i<(N*SEC_BYTES*SEC_BYTES*3); i++) {
    hashing_pot[i] = pks[i];
  }
  for(int i=0, j=(N*SEC_BYTES*SEC_BYTES*3); i<msg_len; i++, j++) {
    hashing_pot[j] = msg[i];
  }
  for(int i=0, j=(N*SEC_BYTES*SEC_BYTES*3)+msg_len; i<(N*SEC_BYTES*SEC_BYTES*3); i++, j++) {
    hashing_pot[j] = c[i];
  }
  u8 target[SEC_BYTES];
  HHash(hashing_pot, hashing_len, target);

  //now compute the XOR of the commitments
  u8 xorreggia[SEC_BYTES] = {0};
  for(int l=0; l<N; l++) {
    for(int i=0; i<SEC_BYTES; i++) {
      xorreggia[i] ^= z[l*SEC_BYTES+i];
    }
  }
  //and check if it corresponds to the target
  #ifdef DEBUG
    if(check_identity(target, xorreggia, SEC_BYTES) == 0) {
      printf("RVer(): the commitments are not correct!");
      print_array(target, SEC_BYTES);
      print_array(xorreggia, SEC_BYTES);
    }
  #endif
  return check_identity(target, xorreggia, SEC_BYTES);
}

/*
 * RTrace outputs 1 if the two signatures came from the same
 * private key, 0 otherwise. 
 * In the first case, it outputs the pointer to the public key 
 * of the ring that signed was used to sign the two signatures.
*/
int RTrace(u8 *pks, unsigned int N, u8 *sig1, u8 *sig2, u8 **point) {
  //theoretically should check there are N pks, the lenght are correct etc
  //but here I cannot check any lenght, should be done before..
  u8 *r1 = sig1+N*SEC_BYTES;
  u8 *r2 = sig2+N*SEC_BYTES;

  for(int l=0; l<N; l++) {
    u8 hashes1[SEC_BYTES*RING_GHASH_OUT];
    u8 hashes2[SEC_BYTES*RING_GHASH_OUT];
    /*
     * Possible parallel optimization:
     * to check multiple signatures in parallel, just hash all the
     * challenges (r), even in parallel, and then XOR the hashes 
     * two by two as done after the merge array.
     */
    for(int i=0; i<SEC_BYTES; i++) {
      GHash(r1+l*SEC_BYTES*SEC_BYTES+SEC_BYTES*i, hashes1+RING_GHASH_OUT*i);
    }
    for(int i=0; i<SEC_BYTES; i++) {
      GHash(r2+l*SEC_BYTES*SEC_BYTES+SEC_BYTES*i, hashes2+RING_GHASH_OUT*i);
    }
    //XOR the two hashes
    u8 merge[SEC_BYTES*SEC_BYTES*3];
    for(int i=0; i<SEC_BYTES*SEC_BYTES*3; i++) {
      merge[i] = hashes1[i] ^ hashes2[i];
    }
    
    for(int i=0; i<SEC_BYTES; i++) {
      for(int j=0; j<SEC_BYTES; j++) {
        if(check_identity(merge+SEC_BYTES*3*i, pks+l*SEC_BYTES*SEC_BYTES*3+SEC_BYTES*3*j, SEC_BYTES*3)) {
          #ifdef DEBUG
          printf("RTrace(): %d and %d are identical\n", i, j);
          #endif
          *point = pks+l*SEC_BYTES*SEC_BYTES*3;
          return 1;
        }
      }
    }
  }
  return 0;
}
/*
 * RTrace outputs the number of signatures that came from the same
 * private key, 0 otherwise.
 * In the first case, it outputs the pointer to the public key 
 * of the ring that signed was used to sign the two signatures.
 * This particurarly optimises the most used case in real life
 * to check in a bow of signatures if there is 
 * 
 * point MUST be declared upfront as u8 *point[N]; (array of pointers)
 */
int RTraces(u8 *pks, unsigned int N, u8 *sigs, unsigned int many_sigs, u8 **point, unsigned int stop_at) {
  //for each member
  for(int l=0; l<N; l++) {
      u8 *r1 = sigs+N*SEC_BYTES;

      u8 hashes[many_sigs*SEC_BYTES*RING_GHASH_OUT];
      for(int k=0; k<many_sigs; k++) {
        for(int i=0; i<SEC_BYTES; i++) {
          int h_point = k*SEC_BYTES*RING_GHASH_OUT + i*RING_GHASH_OUT;
          // sigs + (N*SEC_BYTES+N*SEC_BYTES*SEC_BYTES) + N*SEC_BYTES + 
        }
      }
  }
  //found 0
  return 0;
}