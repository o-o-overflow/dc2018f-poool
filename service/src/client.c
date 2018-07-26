#include "client.h"
#include "daemon.h"

#include "utils.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

struct client *g_client;
pthread_mutex_t g_client_lock;

static void client_init(struct client *c) {
    pthread_mutex_init(&g_client_lock, NULL);
    memset(c, 0, sizeof(struct client));
    c->login_time = time(NULL);
}

void client_send_error(struct client *c, const char *fmt, ...) {
    char error[0x100];
    char buf[0x100];
    va_list args;
    va_start(args, fmt);
    vsnprintf(error, sizeof(error), fmt, args);
    va_end(args);

    int len = snprintf(buf, sizeof(buf),
        "{\"id\":%d,\"result\":false,\"error\":[\"%s\"]}\n", c->id, error);
    write(1, buf, len);

    c->total_error++;
}

void client_send_result(struct client *c, const char *fmt, ...) {
    char result[0x100];
    char buf[0x100];
    va_list args;
    va_start(args, fmt);
    vsnprintf(result, sizeof(result), fmt, args);
    va_end(args);

    int len = snprintf(buf, sizeof(buf),
        "{\"id\":%d,\"result\":%s,\"error\":null}\n", c->id, result);
    write(1, buf, len);
}

void client_send_difficulty(struct client *c) {
    char diff[0x48];
    snprintf(diff, sizeof(diff), "%016lx", c->target);
    memset(&diff[0x10], '0', 0x30);
    diff[0x20] = '\0';
    char buf[0x100];
    int len = snprintf(buf, sizeof(buf),
        "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[\"%s\"]}\n", diff);
    write(1, buf, len);
}

void client_send_job(struct client *c) {
    char buf[0x200];
    char hdr[0x104];

    if (c->job == NULL) {
        c->job = job_next();
    }

    int n = bin2hex((const char *)&c->job->header, hdr, sizeof(c->job->header));
    c->job->header[n] = '\0';

    int len = snprintf(buf, sizeof(buf),
        "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"%08x\",\"%s\",\"%08x\"]}\n",
        c->job->id, hdr, c->job->time);
    write(1, buf, len);
}

static void client_subscribe(struct client *client, struct json_array_s *params) {
    if (client->job != NULL) {
        free(client->job);
    }
    client->job = job_next();
    client->nonce1 = client->job->nonce;
    client->target = CLIENT_DEFAULT_TARGET;

    struct json_value_s *version = json_get_index(params, 0);
    if (version && version->type == json_type_string) {
        strncpy(client->version, ToString(version), sizeof(client->version));
    }

    client_send_result(client, "[null,\"%08x\",4]", client->nonce1);
}

static int valid_username(const char *username) {
    if (username[0] != 'o' || username[1] != 'O' || username[2] != '0') {
        return 0;
    }
    int len = strlen(username);
    if (len != 35) {
        return 0;
    }
    for (int i = 3; i < len; i++) {
        char c = username[i];
        if (!isalnum(c) || c == 'I' || c == 'O' || c == 'l' || c == '0') {
            return 0;
        }
    }
    return 1;
}

static void client_authorize(struct client *client, struct json_array_s *params) {
    if (!client->nonce1) {
        client_send_error(client, "not subscribed");
        return ;
    }

    if (client->authorized) {
        client_send_error(client, "already authorized");
        return ;
    }

    struct json_value_s *username = json_get_index(params, 0);
    if (username && username->type == json_type_string) {
        strncpy(client->username, ToString(username), sizeof(client->username));
    }

    if (!valid_username(client->username)) {
        client_send_error(client, "invalid username");
        return ;
    }

    client->authorized = 1;

    struct json_value_s *password = json_get_index(params, 1);
    if (password && password->type == json_type_string) {
        strncpy(client->password, ToString(password), sizeof(client->password));
    }

    client_send_result(client, "true");
    client_send_difficulty(client);
    client_send_job(client);
}

static void client_submit(struct client *client, struct json_array_s *params) {
    client->last_submission = time(NULL);
    client->total_submission++;
    client->recent_submission++;

    if (client->job == NULL) {
        client_send_error(client, "job not available");
        return ;
    }

    if (params->length < 4) {
        client_send_error(client, "not enough params");
        return ;
    }

    for (int i = 0; i < params->length; i++) {
        struct json_value_s *val = json_get_index(params, i);
        if (!val || val->type != json_type_string || val->type != json_type_number) {
            client_send_error(client, "invalid params");
            return ;
        }
    }

    struct json_value_s *job_id = json_get_index(params, 1);
    uint32_t id = atoi(ToString(job_id));
    if (id != client->job->id) {
        client_send_error(client, "job not found");
        return ;
    }

    struct json_value_s *nonce2 = json_get_index(params, 2);
    struct json_value_s *timestamp = json_get_index(params, 3);

    if (!job_validate(ToString(nonce2), ToString(timestamp))) {
        client_send_error(client, "duplicated share");
        return ;
    }

    // uint64_t diff = job_calc_diff(ToString(nonce2), ToString(timestamp));
    int64_t hash = job_calc_diff(ToString(nonce2), ToString(timestamp));

    if (hash < client->target) {
        client->last_accept = time(NULL);

        uint64_t diff = (~0ULL) / client->target;
        client->share += diff;

        client_send_result(client, "[true]");

        if (hash < CLIENT_FINAL_TARGET) {
            client->share += CLIENT_FINAL_DIFF * 0.3;
            daemon_notify();
        }
    } else {
        client_send_error(client, "low difficulty share");
    }
}

static void client_suggest_target(struct client *client, struct json_array_s *params) {
    struct json_value_s *target = json_get_index(params, 0);
    if (target && target->type == json_type_string) {
        uint64_t tmp;
        hex2bin(ToString(target), (char *)&tmp, 16);
        uint64_t target = SWAP64(tmp);
        if (target >= CLIENT_FINAL_TARGET) {
            client_send_result(client, "true");
            client->target = target;
            client_send_difficulty(client);
            client->job = job_next();
            client_send_job(client);
            return ;
        }
    }
    client_send_error(client, "invalid difficulty");
}

static void client_send_flag(struct client *client, struct json_array_s *params) {
    char bits[CLIENT_FLAG_BITS + 1];
    int i;
    uint32_t limit = client->balance / CLIENT_FLAG_PRICE_PER_BIT;
    if (limit > CLIENT_FLAG_BITS) {
        limit = CLIENT_FLAG_BITS;
    }
    if (limit > params->length) {
        limit = params->length;
    }

    const char *flag = getflag();
    for (i = 0; i < limit; i++) {
        struct json_value_s *idx = json_get_index(params, i);
        if (idx == NULL || idx->type != json_type_number) {
            break;
        } else {
            uint8_t bit = atoi(ToString(idx));
            uint8_t c = flag[bit / 8];
            bits[i] = ((c >> (bit % 8)) & 1) ? '1' : '0';
        }
    }
    client->balance -= CLIENT_FLAG_PRICE_PER_BIT * i;
    bits[i] = '\0';

    client_send_result(client, "\"%s\"", bits);
}

void *client_thread(void *args) {
    struct client C;
    struct client *client = &C;
    client_init(client);

    g_client = client;

    while (!client->stop) {
        if (client->total_error > CLIENT_BAD_LIMINT) {
            break;
        }

        struct json_value_s *obj_raw = nextjson(client);

        if (!obj_raw || !obj_raw->payload) {
            break;
        }

        struct json_object_s *obj = (struct json_object_s *)obj_raw->payload;

        pthread_mutex_lock(&g_client_lock);

        struct json_value_s *id = json_get_value(obj, "id");
        if (!id) {
            client->id = 0;
        } else {
            client->id = atoi(ToString(id));
        }

        struct json_value_s *method = json_get_value(obj, "method");

        if (!method || !method->payload) {
            client_send_error(client, "no method");
            goto unlock;
        }

        struct json_value_s *params_raw = json_get_value(obj, "params");
        if (!params_raw || !params_raw->payload) {
            client_send_error(client, "no params");
            goto unlock;
        }

        struct json_array_s *params = (struct json_array_s *)params_raw->payload;

        const char *method_str = ToString(method);

        if (!strcmp(method_str, "mining.subscribe")) {
            client_subscribe(client, params);
        } else if (!strcmp(method_str, "mining.authorize")) {
            client_authorize(client, params);
        } else if (!strcmp(method_str, "mining.ping")) {
            client_send_result(client, "\"pong\"");
        } else if (!strcmp(method_str, "mining.submit")) {
            client_submit(client, params);
        } else if (!strcmp(method_str, "mining.suggest_target")) {
            client_suggest_target(client, params);
        } else if (!strcmp(method_str, "mining.suggest_difficulty")) {
            client_send_result(client, "true");
        } else if (!strcmp(method_str, "get_transactions")) {
            client_send_result(client, "[]");
        } else if(!strcmp(method_str, "mining.multi_version")) {
            client_send_result(client, "false");
        } else if(!strcmp(method_str, "mining.extranonce.subscribe")) {
            client_send_result(client, "false");
        } else if(!strcmp(method_str, "client.stats.speed")) {
            time_t now = time(NULL);
            double period = now - client->login_time;
            client_send_result(client, "\"%lfKH/s\"", client->share / period / 1000.);
        } else if(!strcmp(method_str, "client.stats.share")) {
            client_send_result(client, "%lld", client->share);
        } else if(!strcmp(method_str, "client.stats.balance")) {
            client_send_result(client, "\"%lld OOO\"", client->balance);
        } else if(!strcmp(method_str, "client.exchange.flag")) {
            client_send_flag(client, params);
        } else {
            client_send_error(client, "'%s' is not supported", method_str);
        }

unlock:
        pthread_mutex_unlock(&g_client_lock);

        free(obj_raw);
    }

    return NULL;
}
