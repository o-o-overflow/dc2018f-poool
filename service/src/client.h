#ifndef _CLIENT_H
#define _CLIENT_H

#include "job.h"

#include <time.h>
#include <pthread.h>

#define CLIENT_BUFSIZE 0x1000
#define CLIENT_BAD_LIMINT 8
// The hashing power of my laptop is about 50H/s (single core under docker),
// so the expected time for default task is about 0x200 / 50 = 10.24s, which
// fits in a difficulty adjustment period.
#define CLIENT_DEFAULT_TARGET 0x80000000000000ULL
#define CLIENT_DEFAULT_DIFF 0x200
#define CLIENT_INVALID_TARGET 0x4000000000000000ULL
#define CLIENT_FINAL_TARGET 0x20000000000L
// It takes 4096 Cores machine to run more than 1 min to get enough share. Hope
// it's heavy enough since it only worths one flag.
#define CLIENT_FINAL_DIFF 0x800000
#define CLIENT_FLAG_BITS 0xc0
// We should be able to fetch 1 bit of the flag in about 10s on average.
#define CLIENT_FLAG_PRICE_PER_BIT (CLIENT_FINAL_DIFF / CLIENT_FLAG_BITS)

struct client {
    size_t buf_len;
    time_t login_time;
    time_t last_read;
    time_t last_accept;
    time_t last_submission;
    uint32_t total_read;
    uint32_t total_error;
    uint32_t recent_submission;
    uint32_t total_submission;
    uint32_t id;
    uint8_t stop;
    uint8_t authorized;
    struct job *job;
    uint64_t target;
    uint64_t share;
    uint64_t total_share;
    uint64_t balance;
    uint32_t nonce1;
    char version[0x20];
    char username[0x24];
    char password[0x20];
    char buf[CLIENT_BUFSIZE];
};

void *client_thread(void *args);

void client_send_difficulty(struct client *c);

void client_send_job(struct client *c);

extern struct client *g_client;
extern pthread_mutex_t g_client_lock;

#endif
