//https://eprint.iacr.org/2021/1054.pdf
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sha256.h"

typedef unsigned char u8;
//secure bits parameter. Test is 4, implementation is 16
#define SEC_BYTES 16
//TO-DO: define all these dimensions
#define PK_LEN SEC_BYTES*SEC_BYTES*3

int check_identity(u8 *arr1, u8 *arr2, int len) {
  //very effective because aborts at the first !=
  for(int i =0; i<len; i++) {
    if(arr1[i] != arr2[i]) {
      return 0;
    }
  }
  return 1;
}
//size is the size of each element
//count is how many there are 
int test_uniqness(u8 *arr, int size, int count) {
  //other test on checking distinct
  //idea is like 5 elements: 1,2,3,4,5
  // first round: check 1-2, 1-3, 1-4, 1-5
  // second round: check 2-3, 2-4, 2-5
  // third round: check 3-4, 3-5
  // fourth round: check 4-5
  for(int i=0; i<count-1; i++) {
    for(int j=i+1; j<count; j++) {
      printf("testing %d-%d\n", i, j);
      if(check_identity(arr+i*size, arr+j*size, size)) {
        return 0;
      }
    }
  }
  return 1;
}
int rand_lim(int limit) {
  /*
    int divisor = RAND_MAX/(limit+1);
    int retval;
    do { 
        retval = rand() / divisor;
    } while (retval > limit);

    return retval;
  it's slow and the actual random difference is not that big so that there could be an actual attack */
  return rand() % limit;
}
void random_array(u8 *input, unsigned int array_len) {
  for(int i=0; i<array_len; i++) {
    input[i] = rand_lim(256);
  }
}
void print_array(u8 *array, int len) {
  printf("[");
  for(int loop = 0; loop < len-1; loop++)
      printf("%d, ", array[loop]);
  printf("%d", array[len-1]);
  printf("]\n");
}
//input[SEC_BYTES]
//output[SEC_BYTES*3]
void GHash(u8 *input, u8 *output) {
  SHA256_CTX ctx;
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
//input[input_len]
//output[SEC_BYTES]
void HHash(u8 *input, unsigned int input_len, u8 *output) {
  SHA256_CTX ctx;
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
// outputs pk[3l], sk[2l]
void GenerateKeys(u8 *pk, u8 *sk) {
  //generate the 2 secret seeds at the same time
  random_array(sk, SEC_BYTES*SEC_BYTES*2);
  u8 g_1[SEC_BYTES*SEC_BYTES*3], g_2[SEC_BYTES*SEC_BYTES*3];
  for(int i=0; i<SEC_BYTES; i++) {
    GHash(sk+i*SEC_BYTES, g_1+i*SEC_BYTES*3);
    GHash(sk+SEC_BYTES*SEC_BYTES+i*SEC_BYTES, g_2+i*SEC_BYTES*3);
  }
  printf("g_1: "); print_array(g_1, SEC_BYTES*SEC_BYTES*3);
  printf("g_2: "); print_array(g_2, SEC_BYTES*SEC_BYTES*3);
  for(int i=0; i<SEC_BYTES*SEC_BYTES*3; i++) {
    pk[i] = g_1[i] ^ g_2[i];
  }
}

//pks[pk1, pk2 ... pk_pos ... pk_N]
//sk[g_1, g_2]
//msg[msg_len]
void RSign(u8 *pks, unsigned int N, u8 *sk, unsigned int pos, u8 *msg, unsigned int msg_len, u8 *sigout) {
  u8 c[N*SEC_BYTES*SEC_BYTES*3];
  //z is each commitment, which is a random string
  u8 z[N*SEC_BYTES];
  random_array(z, N*SEC_BYTES);
  printf("z-strings[%d]: ", N*SEC_BYTES); print_array(z, N*SEC_BYTES);
  //fictional seeds
  u8 r[N*SEC_BYTES*SEC_BYTES];
  random_array(r, N*SEC_BYTES*SEC_BYTES);
  printf("r-seeds[%d]: ", N*SEC_BYTES*SEC_BYTES); print_array(r, N*SEC_BYTES*SEC_BYTES);
  for(unsigned int l=0; l < N; l++ ) {
    printf("! computing l=%d\n", l);
    if(l == pos) {
      //since above we have generated  all the strings, reset to 0 this position so that the XOR doesn't change
      for(int i=pos*SEC_BYTES; i < pos*SEC_BYTES + SEC_BYTES; i++) {
        z[i] = 0;
      }
      //set the c for this one
      for(int i=0; i<SEC_BYTES; i++) {
        int c_pos = pos*SEC_BYTES*SEC_BYTES*3 + i*SEC_BYTES*3;
        GHash(sk+SEC_BYTES*i, c+c_pos);
        printf("aftr GHash c[%d, %d-%d][%d]: ", N*SEC_BYTES*SEC_BYTES*3, c_pos, c_pos+SEC_BYTES*3, SEC_BYTES*3); print_array(c+c_pos, SEC_BYTES*3);
      }
    } else {
      //the random string has been already generated and also the random seed
      
      //now commit to the random string using the i-th public key
      //for each bit of z, use the rj_seed[SEC_BYTES] corresponding. Take that rj_seed, put it in G and if z_i is 1, XOR is with the corresponding subsection of the public key[SEC_BYTES*3]
      for(int i=0; i<SEC_BYTES; i++) {
        int c_pos = l*SEC_BYTES*SEC_BYTES*3 + i*SEC_BYTES*3;
        int r_pos = l*SEC_BYTES*SEC_BYTES + i*SEC_BYTES;
        printf(" - iteration %d, c_pos=%d, r_pos=%d\n", i, c_pos, r_pos);
        GHash(r+r_pos, c+c_pos);
        
        printf("aftr GHash c[%d, %d-%d][%d]: ", N*SEC_BYTES*SEC_BYTES*3, c_pos, c_pos+SEC_BYTES*3, SEC_BYTES*3); print_array(c+c_pos, SEC_BYTES*3);
        printf("z-string committment %d-->%d\n", z[l*SEC_BYTES+i], z[l*SEC_BYTES+i]%2);
        //now if the committing bit z[i] is 1, proceed to XOR this individual SEC_BYTES*3 section of c with the pubic key
        //since there is some trouble, meant to be a bit, but would be too much hard, I just convert it to a pseudo bit by making the modulo
        if(z[l*SEC_BYTES+i]%2) {
          for(int e=c_pos; e<c_pos+SEC_BYTES*3; e++) {
            printf("  xoring c=%d position %d with pk=%d position %d\n", c[e], e, pks[e], e);
            c[e] ^= pks[e];
          }
        }
      }
    }
  }
  printf("=finished step 3=\n");
  printf("z-strings[%d]: ", N*SEC_BYTES); print_array(z, N*SEC_BYTES);
  printf("c[%d]: ", N*SEC_BYTES*SEC_BYTES*3); print_array(c, N*SEC_BYTES*SEC_BYTES*3);
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
  printf("hashing_pot[%d]: ", hashing_len); print_array(hashing_pot, hashing_len);
  u8 target[SEC_BYTES];
  HHash(hashing_pot, hashing_len, target);
  printf("target[%d]: ", SEC_BYTES); print_array(target, SEC_BYTES);
  //zl is the adjustment with the XOR so that the xor of all z 's is equal to the target.
  ///u8 zl[SEC_BYTES];
  //first of all lets "XOR" this 0's zl with the target
  for(int i=0; i<SEC_BYTES; i++) {
    z[pos*SEC_BYTES+i] = target[i];
  }
  //then for all the committments except zl
  for(int l=0; l<N; l++) {
    if(l==pos) {
      continue;
    }
    //I don't know if this particular nested loop is efficient
    printf("xoring with z-string %d [%d]: ", l, SEC_BYTES); print_array(z+l*SEC_BYTES, SEC_BYTES);
    for(int i=0; i<SEC_BYTES; i++) {
      z[pos*SEC_BYTES+i] ^= z[l*SEC_BYTES+i];
    }
  }
  printf("zl[%d]: ", SEC_BYTES); print_array(z+pos*SEC_BYTES, SEC_BYTES);
  
  //now equivocate pos committments(c) so that it opens to zl
  for(int i=0; i<SEC_BYTES; i++) {
    // the r of pos goes from pos*SEC_BYTES*SEC_BYTES to pos*SEC_BYTES*SEC_BYTES+SEC_BYTES*SEC_BYTES
    //first of all understand if to use seed1 or seed2 (namely g_1 g_2)
    int pseudo_zbit = z[pos*SEC_BYTES+i]%2;
    int base_seedlocation = pseudo_zbit*SEC_BYTES*SEC_BYTES+i*SEC_BYTES;
    int base_rseed = pos*SEC_BYTES*SEC_BYTES+i*SEC_BYTES;
    //copy the chunk of SEC_BYTES
    for(int j=0; j<SEC_BYTES; j++) {
      r[base_rseed+j] = sk[base_seedlocation+j];
    }
  }

  //now computing is finished. Output consists of R, sig and msg
  //output[pks, z, r, msg, msg_len]
  //int output_len = (N*SEC_BYTES*SEC_BYTES*3) + N*SEC_BYTES + N*SEC_BYTES*SEC_BYTES + msg_len;
  //signature[z,r]
  //int sig_len = N*SEC_BYTES + N*SEC_BYTES*SEC_BYTES;
  //int sig[sig_len];
  for(int i=0; i<N*SEC_BYTES; i++) {
    sigout[i] = z[i];
  }
  for(int i=0, j=(N*SEC_BYTES); i<N*SEC_BYTES*SEC_BYTES; i++, j++) {
    sigout[j] = r[i];
  }
  printf("z[%d]: ", N*SEC_BYTES); print_array(z, N*SEC_BYTES);
  printf("r[%d]: ", N*SEC_BYTES*SEC_BYTES); print_array(r, N*SEC_BYTES*SEC_BYTES);
}

//pks[N*SEC_BYTES*SEC_BYTES*3]: public keys
//N: number of public keys
//msg: msg that was used to sign
//msg_len: its lenght
//sigs{z[N*SEC_BYTES] + r[N*SEC_BYTES*SEC_BYTES]} <--> 
int RVer(u8 *pks, unsigned int N, u8 *msg, unsigned int msg_len, u8 *sigs) {
  //check all the elements are distinct  
  if(!test_uniqness(pks, SEC_BYTES*SEC_BYTES*3, N)) {
    //keys not distinct
    printf("the keys are not distict!");
    return 0;
  }
  //committments
  u8 c[N*SEC_BYTES*SEC_BYTES*3];
  u8 *z = sigs;
  u8 *r = sigs+N*SEC_BYTES;
  for(int l=0; l<N; l++) {
    for(int i=0; i<SEC_BYTES; i++) {
      int c_pos = l*SEC_BYTES*SEC_BYTES*3 + i*SEC_BYTES*3;
      int r_pos = l*SEC_BYTES*SEC_BYTES + i*SEC_BYTES;
      GHash(r+r_pos, c+c_pos);
      if(sigs[l*SEC_BYTES+i]%2) {
        for(int e=c_pos; e<c_pos+SEC_BYTES*3; e++) {
            printf("  xoring c=%d position %d with pk=%d position %d\n", c[e], e, pks[e], e);
            c[e] ^= pks[e];
          }
      }
    }
  }
  printf("c[%d]: ", N*SEC_BYTES*SEC_BYTES*3); print_array(c, N*SEC_BYTES*SEC_BYTES*3);
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
  printf("hashing_pot[%d]: ", hashing_len); print_array(hashing_pot, hashing_len);
  u8 target[SEC_BYTES];
  HHash(hashing_pot, hashing_len, target);
  printf("target[%d]: ", SEC_BYTES); print_array(target, SEC_BYTES);
  //now compute the XOR of all xi
  u8 xorreggia[SEC_BYTES] = {0};
  for(int l=0; l<N; l++) {
    printf("xoring with z-string %d [%d]: ", l, SEC_BYTES); print_array(z+l*SEC_BYTES, SEC_BYTES);
    for(int i=0; i<SEC_BYTES; i++) {
      xorreggia[i] ^= z[l*SEC_BYTES+i];
    }
  }
  printf("xorreggia[%d]: ", SEC_BYTES); print_array(xorreggia, SEC_BYTES);
  return check_identity(target, xorreggia, SEC_BYTES);
}
//l will output where is the Trace
int Trace(u8 *pks, unsigned int N, u8 *sig1, u8 *sig2, u8 **point) {
  //theoretically should check there are N pks, the lenght are correct etc
  //but here I cannot check any lenght
  u8 *r1 = sig1+N*SEC_BYTES;
  u8 *r2 = sig2+N*SEC_BYTES;
  //now we hash 
  //special note: the ring in both signatures is THE SAME, so for each position, the public key is the same. So what I'm supposed to do is do SEC_BYTES * SEC_BYTES calculations for each N
  printf("sig1[%d]: ", 2*SEC_BYTES + 2*SEC_BYTES*SEC_BYTES); print_array(sig1, 2*SEC_BYTES + 2*SEC_BYTES*SEC_BYTES);
  printf("sig2[%d]: ", 2*SEC_BYTES + 2*SEC_BYTES*SEC_BYTES); print_array(sig2, 2*SEC_BYTES + 2*SEC_BYTES*SEC_BYTES);
  printf("r1[%d]: ", N*SEC_BYTES*SEC_BYTES); print_array(r1, N*SEC_BYTES*SEC_BYTES);
  printf("r2[%d]: ", N*SEC_BYTES*SEC_BYTES); print_array(r2, N*SEC_BYTES*SEC_BYTES);

  for(int l=0; l<N; l++) {
    u8 hashes1[SEC_BYTES*SEC_BYTES*3];
    u8 hashes2[SEC_BYTES*SEC_BYTES*3];
    for(int i=0; i<SEC_BYTES; i++) {
      GHash(r1+l*SEC_BYTES*SEC_BYTES+SEC_BYTES*i, hashes1+SEC_BYTES*3*i);
      printf("r1[%d]: ", SEC_BYTES); print_array(r1+l*SEC_BYTES*SEC_BYTES+SEC_BYTES*i, SEC_BYTES);
      printf("h1[%d]: ", SEC_BYTES*3); print_array(hashes1+SEC_BYTES*3*i, SEC_BYTES*3);

    }
    for(int i=0; i<SEC_BYTES; i++) {
      GHash(r2+l*SEC_BYTES*SEC_BYTES+SEC_BYTES*i, hashes2+SEC_BYTES*3*i);
      printf("r2[%d]: ", SEC_BYTES); print_array(r2+l*SEC_BYTES*SEC_BYTES+SEC_BYTES*i, SEC_BYTES);
      printf("h2[%d]: ", SEC_BYTES*3); print_array(hashes2+SEC_BYTES*3*i, SEC_BYTES*3);

    }
    u8 merge[SEC_BYTES*SEC_BYTES*3];
    for(int i=0; i<SEC_BYTES*SEC_BYTES*3; i++) {
      merge[i] = hashes1[i] ^ hashes2[i];
    }
    printf("hashes1[%d]: ", SEC_BYTES*SEC_BYTES*3); print_array(hashes1, SEC_BYTES*SEC_BYTES*3);
    printf("hashes2[%d]: ", SEC_BYTES*SEC_BYTES*3); print_array(hashes2, SEC_BYTES*SEC_BYTES*3);
    printf("merge[%d]: ", SEC_BYTES*SEC_BYTES*3); print_array(merge, SEC_BYTES*SEC_BYTES*3);
    printf("pk[%d]: ", SEC_BYTES*SEC_BYTES*3); print_array(pks+l*SEC_BYTES*SEC_BYTES*3, SEC_BYTES*SEC_BYTES*3);
    
    for(int i=0; i<SEC_BYTES; i++) {
      for(int j=0; j<SEC_BYTES; j++) {
        printf("checking %d merge[%d]: ", i, SEC_BYTES*3); print_array(merge+SEC_BYTES*3*i, SEC_BYTES*3);
        printf("checking %d pks[%d]: ", j, SEC_BYTES*3); print_array(pks+l*SEC_BYTES*SEC_BYTES*3+SEC_BYTES*3*j, SEC_BYTES*3);
        if(check_identity(merge+SEC_BYTES*3*i, pks+l*SEC_BYTES*SEC_BYTES*3+SEC_BYTES*3*j, SEC_BYTES*3)) {
          printf("%d and %d are identical\n", i, j);
          *point = pks+l*SEC_BYTES*SEC_BYTES*3;
          printf("pk[%d]: ", SEC_BYTES*SEC_BYTES*3); print_array(pks+l*SEC_BYTES*SEC_BYTES*3, SEC_BYTES*SEC_BYTES*3);
          printf("pk[%d]: ", SEC_BYTES*SEC_BYTES*3); print_array(*point, SEC_BYTES*SEC_BYTES*3);
          return 1;
        }
      }
    }
  }
  return 0;
}

int main(void) {
//initialise the random
  srand(time(NULL));
  
  printf("Info OTRS. \nsecurity bytes %d; security bits %d\n\n", SEC_BYTES, SEC_BYTES*8);
  // variables for public key and secret one
  /*
  u8 pk[SEC_BYTES*SEC_BYTES*3], sk[SEC_BYTES*SEC_BYTES*2];
  GenerateKeys(pk, sk);
  printf("sk: "); print_array(sk, SEC_BYTES*SEC_BYTES*2);
  printf("pk: "); print_array(pk, SEC_BYTES*SEC_BYTES*3);*/

  //SIGN TEST SECTION
  // generate another public key
  u8 ring[2*SEC_BYTES*SEC_BYTES*3];
  u8 sk[SEC_BYTES*SEC_BYTES*2];
  GenerateKeys(ring, sk);
  GenerateKeys(ring+SEC_BYTES*SEC_BYTES*3, sk); //overwrites
  printf("\n=== GENERATED KEYS ===\n");
  printf("sk: "); print_array(sk, SEC_BYTES*SEC_BYTES*2);
  printf("pk: "); print_array(ring, SEC_BYTES*SEC_BYTES*3);
  printf("pk_i: "); print_array(ring+SEC_BYTES*SEC_BYTES*3, SEC_BYTES*SEC_BYTES*3);
  printf("======================\n");
  u8 sigout[2*SEC_BYTES + 2*SEC_BYTES*SEC_BYTES];
  printf("\n=== SIGNING MESSAGE ===\n");
  RSign(ring, 2, sk, 1, (u8 []) {0,22,55,7}, 4, sigout);
  printf("======================\n");
  printf("sigout: "); print_array(sigout, 2*SEC_BYTES + 2*SEC_BYTES*SEC_BYTES);
  
  //Verification section
  printf("\n=== VERIFYING MESSAGE ===\n");
  int result = RVer(ring, 2, (u8 []){0,22,55,2}, 4, sigout);
  printf("the signature is %d\n",result);
  printf("======================\n");
  u8 sigout2[2*SEC_BYTES + 2*SEC_BYTES*SEC_BYTES];
  RSign(ring, 2, sk, 1, (u8 []) {0,22,57,2}, 4, sigout2);
  //Trace section
  printf("\n=== TRACING SIGS MESSAGE ===\n");
  u8 *l;
  int trace = Trace(ring, 2, sigout, sigout2, &l);
  if(trace) {
    printf("\n pk of trace: "); print_array(l, SEC_BYTES*SEC_BYTES*3);
  }
  printf("the trace is %d\n",trace);
  printf("======================\n");
}



