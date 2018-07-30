#include "job.h"
#include "crypto.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>

static struct job *g_job;

static pthread_mutex_t g_solution_lock;
static struct solution *g_solutions;

struct job *job_next() {
    if (g_job == NULL) {
        pthread_mutex_init(&g_solution_lock, NULL);

        g_job = calloc(1, sizeof(struct job));
        g_job->id = 0;
        g_job->time = 0;
        g_job->nonce = randint();

        const char *flag = getflag();
        unsigned char curr[SHA256_DIGEST_LENGTH];
        unsigned char prev[SHA256_DIGEST_LENGTH];

        SHA256(flag, strlen(flag), (unsigned char *)&prev);
        for (int i = 0; i < sizeof(g_job->header); i += SHA256_DIGEST_LENGTH) {
            SHA256(prev, sizeof(prev), (unsigned char *)&curr);
            memcpy(&g_job->header[i], curr, sizeof(curr));
            memcpy(prev, curr, sizeof(curr));
        }
    }
    g_job->id++;
    struct job *j = malloc(sizeof(struct job));
    *j = *g_job;
    j->time = time(NULL);
    return j;
}

int job_validate(const char *nonce2, const char *timestamp) {
    if (strlen(nonce2) != 8 || strlen(timestamp) != 8) {
        return 0;
    }
    struct solution *soln = malloc(sizeof(struct solution));
    memcpy(soln->nonce2, nonce2, sizeof(soln->nonce2));
    memcpy(soln->time, timestamp, sizeof(soln->time));
    soln->next = NULL;

    int valid = 1;

    pthread_mutex_lock(&g_solution_lock);
    for (struct solution *s = g_solutions; s; s = s->next) {
        if (!memcmp(s, soln, sizeof(soln->nonce2) + sizeof(soln->time))) {
            valid = 0;
            break;
        }
    }
    if (valid) {
        soln->next = g_solutions;
        g_solutions = soln;
    }
    pthread_mutex_unlock(&g_solution_lock);

    if (!valid) {
        free(soln);
    }
    return valid;
}

uint64_t job_calc_diff(const char *nonce2, const char *timestamp) {
    const size_t header_size = sizeof(g_job->header);
    uint8_t block[header_size + sizeof(uint32_t) * 4];
    memcpy(block, g_job->header, header_size);

    uint32_t *ints = (uint32_t *)&block[header_size];
    uint32_t tmp;

    ints[0] = g_job->nonce;

    sscanf(timestamp, "%8x", &tmp);
    ints[1] = tmp;

    sscanf(nonce2, "%8x", &tmp);
    ints[2] = tmp;
    ints[3] = '0oO\0';

    uint8_t hash[SHA256_DIGEST_LENGTH];
    ooo_hash(block, sizeof(block), (uint8_t *)&hash);
    return SWAP64(*(uint64_t *)&hash);
}

void job_prune() {
    pthread_mutex_lock(&g_solution_lock);
    for (struct solution *s = g_solutions; s;) {
        struct solution *next = s->next;
        free(s);
        s = next;
    }
    g_solutions = NULL;
    pthread_mutex_unlock(&g_solution_lock);
}