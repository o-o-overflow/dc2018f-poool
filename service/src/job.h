#ifndef _JOB_H
#define _JOB_H

#include <stdint.h>

struct job {
    uint32_t id;
    uint32_t nonce;
    uint32_t time;
    uint32_t target;
    uint8_t header[0x80];
};

struct solution {
    char nonce2[8];
    char time[8];
    struct solution *next;
};

struct job *job_next();

int job_validate(const char *nonce2, const char *timestamp);

uint64_t job_calc_diff(const char *nonce2, const char *timestamp);

void job_prune();

#endif