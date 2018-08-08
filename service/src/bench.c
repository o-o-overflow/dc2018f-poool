#include "crypto.h"
#include "job.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s count", argv[0]);
    } else {
        uint32_t count = strtoull(argv[1], NULL, 10);

        size_t header_size = (size_t)&((struct job *)0)->header;
        uint8_t block[header_size + sizeof(uint32_t) * 4];
        memset(block, 'A', sizeof(block));

        uint32_t *nonce = (uint32_t *)&block[header_size];
        nonce[1] = time(NULL); // timestamp

        uint8_t hash[SHA256_DIGEST_LENGTH];
        memset(hash, 0, sizeof(hash));
        uint64_t *head = (uint64_t *)&hash;

        clock_t start = clock();
        uint64_t minimal = ~0ULL;
        for (uint32_t i = 0; i < count; i++) {
            *nonce = i;
            ooo_hash(block, sizeof(block), hash);
            if (*head < minimal) {
                minimal = *head;
            }
        }
        uint64_t difficulty = ~0ULL / minimal;
        clock_t used = clock() - start;
        float total_time = (float)(used) / CLOCKS_PER_SEC;
        float speed = count / total_time;
        printf("calculate %d hashes in %f speed %fH/s maximal diff = %ld\n", count, total_time, speed, difficulty);
    }
}
