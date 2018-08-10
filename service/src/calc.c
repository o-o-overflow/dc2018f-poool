#include "crypto.h"
#include "utils.h"
#include "job.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/sha.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s header diff [threads] [timeout]\n", argv[0]);
    } else {
        uint32_t diff = strtoull(argv[2], NULL, 10);
        uint32_t threads = (argc >= 4 ? atoi(argv[3]): 4);
        uint32_t timeout = (argc >= 5 ? atoi(argv[4]): 0);

        size_t header_size = sizeof(((struct job *)0)->header);
        uint8_t block[header_size + sizeof(uint32_t) * 4];
        memset(block, 0, sizeof(block));
        hex2bin(argv[1], block, strlen(argv[1]));

        uint32_t *nonce = (uint32_t *)&block[header_size];
        nonce[3] = '0oO\0';

        uint8_t hash[SHA256_DIGEST_LENGTH];
        memset(hash, 0, sizeof(hash));
        uint64_t *head = (uint64_t *)&hash;

        uint64_t step = 0x100000000ULL / threads;

        int *childs = calloc(threads, sizeof(int));

        for (int i = 0; i < threads; i++) {
            int pid = fork();
            if (!pid) {
                for (uint32_t j = 0; j < step; j++) {
                    nonce[2] = step * i + j;
                    ooo_hash(block, sizeof(block), hash);
                    uint64_t difficulty = ~0ULL / SWAP64(*head);
                    if (difficulty > diff) {
                        char hash_h[SHA256_DIGEST_LENGTH * 2 + 1];
                        bin2hex(hash, hash_h, sizeof(hash));
                        hash_h[SHA256_DIGEST_LENGTH * 2] = 0;
                        printf("%#x %s %ld\n", nonce[2], hash_h, difficulty);
                        if (!timeout)
                            exit(1);
                    }
                }
                exit(0);
            } else {
                childs[i] = pid;
            }
        }
        if (timeout) {
            sleep(timeout);
        } else {
            wait(NULL);
        }
        for (int i = 0; i < threads; i++) {
            kill(childs[i], SIGKILL);
        }
    }
}
