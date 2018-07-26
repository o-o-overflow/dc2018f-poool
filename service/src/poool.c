#include <stdio.h>
#include <pthread.h>
#include <time.h>

#include "daemon.h"
#include "client.h"
#include "utils.h"

int main() {
    pthread_t daemon, client;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    pthread_create(&daemon, NULL, daemon_thread, NULL);
    pthread_create(&client, NULL, client_thread, NULL);
    pthread_join(client, NULL);
    return 0;
}
