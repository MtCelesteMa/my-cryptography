#include <stdio.h>
#include <time.h>
#include "ring.h"

#define DEBUG

void gen_test_benchmark() {
    u8 ring[2*SEC_BYTES*SEC_BYTES*3];
    u8 sk[SEC_BYTES*SEC_BYTES*2];
    keygen(ring, sk);
}

void sign_test_benchmark(u8 *ring, int ring_size, u8 *sk, u8 *msg, int msg_len, u8 *sigout) {
    
    if(RVer(ring, ring_size, msg, msg_len, sigout)==0) {
        printf("Signature NOT verified\n");
    }
}
/*
void benchmark(int ring_size, int repeat) {

    u8 ring[ring_size*SEC_BYTES*SEC_BYTES*3];
    u8 sk[SEC_BYTES*SEC_BYTES*2];
    for(int i = 0; i < ring_size; i++) {
        keygen(ring+i*SEC_BYTES*SEC_BYTES*3, sk);
    }
    clock_t start_time = clock();
    for(int i = 0; i < repeat; i++) {
        sign_test_benchmark(ring, ring_size, sk, (u8 []){3,4,5,6}, 4);
    }
    // code or function to benchmark

    double elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    //printf("Done in %f seconds,\n%fms\n%fms each\n", elapsed_time, 
    //elapsed_time*1000, elapsed_time*1000/repeat);
    printf("|sign N=%d| %d | %fms | %fms |\n", ring_size, repeat, elapsed_time*1000, elapsed_time*1000/repeat);
}
*/
void benchmark(int ring_size, int repeat) {

    u8 ring[ring_size*SEC_BYTES*SEC_BYTES*3];
    u8 sk[SEC_BYTES*SEC_BYTES*2];
    for(int i = 0; i < ring_size; i++) {
        keygen(ring+i*SEC_BYTES*SEC_BYTES*3, sk);
    }
    u8 sigout[ring_size*SEC_BYTES + ring_size*SEC_BYTES*SEC_BYTES*3];
    RSign(sigout, ring, ring_size, sk, ring_size-1, (u8 []){3,4,5,6}, 4);

    clock_t start_time = clock();
    for(int i = 0; i < repeat; i++) {
        sign_test_benchmark(ring, ring_size, sk, (u8 []){3,4,5,6}, 4, sigout);
    }
    // code or function to benchmark

    double elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    //printf("Done in %f seconds,\n%fms\n%fms each\n", elapsed_time, 
    //elapsed_time*1000, elapsed_time*1000/repeat);
    printf("|verify N=%d| %d | %fms | %fms |\n", ring_size, repeat, elapsed_time*1000, elapsed_time*1000/repeat);
}
int main(void) {
    printf("THIS IS A TEST PROGRAM\n");
    /*
    u8 ring[2*SEC_BYTES*SEC_BYTES*3];
  u8 sk[SEC_BYTES*SEC_BYTES*2];
  keygen(ring, sk);
  keygen(ring+SEC_BYTES*SEC_BYTES*3, sk); //overwrites
  printf("\n=== GENERATED KEYS ===\n");
  printf("sk: "); print_array(sk, SEC_BYTES*SEC_BYTES*2);
  printf("pk: "); print_array(ring, SEC_BYTES*SEC_BYTES*3);
  printf("pk_i: "); print_array(ring+SEC_BYTES*SEC_BYTES*3, SEC_BYTES*SEC_BYTES*3);
  printf("======================\n");
  */
 /*
    benchmark(2, 1000);
    
    benchmark(16, 1000);
    
    benchmark(32, 1000);
    benchmark(64, 1000);
    benchmark(128, 1000);
    benchmark(256, 1000);
    benchmark(512, 100);*/
    benchmark(1024, 12);
    
    return 1;
}