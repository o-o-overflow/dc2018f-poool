#include "daemon.h"
#include "job.h"
#include "client.h"

#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>

static int daemon_pipe[2];

void *daemon_thread(void *args) {
    pipe(daemon_pipe);

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(daemon_pipe[0], &fdset);

    struct timeval timeout;

    while (1) {
        timeout.tv_sec = 15;
        timeout.tv_usec = 0;

        int ret = select(1, &fdset, NULL, NULL, &timeout);

        pthread_mutex_lock(&g_client_lock);

        // adjust difficulty
        if (g_client->job && !g_client->recent_submission) {
            // too hard?
            uint64_t target = g_client->target / 4;
            target *= 3;
            target += 0x2000000000000000ULL;
            if (target < g_client->target || target > CLIENT_INVALID_TARGET) {
                // seems dead
                g_client->stop = 1;
            } else {
                g_client->target = target;
                client_send_difficulty(g_client);
            }
        } else if (g_client->recent_submission > 15) {
            // too fast?
            uint64_t diff = (~0ULL) / g_client->target;
            diff *= g_client->recent_submission / 5;
            if (diff > CLIENT_FINAL_DIFF) {
                diff = CLIENT_FINAL_DIFF;
            }
            g_client->target = (~0ULL) / diff;
            client_send_difficulty(g_client);
        }

        // balance auto exchange
        g_client->balance += g_client->share;
        g_client->share = 0;

        if (ret > 0) {
            // current job is solved
            char c;
            read(daemon_pipe[0], &c, 1);

            void *old_job = g_client->job;
            g_client->job = job_next();
            free(old_job);
            client_send_job(g_client);
            job_prune();
        }

        pthread_mutex_unlock(&g_client_lock);
    }

    return NULL;
}

void daemon_notify() {
    char c = 0;
    write(daemon_pipe[1], &c, 1);
}