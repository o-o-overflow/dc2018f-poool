#include "utils.h"
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

const char *g_flag;

const char *getflag() {
    if (g_flag) {
        return g_flag;
    }
    char buf[0x100];
    int fd = open("/flag", O_RDONLY);
    if (fd != -1) {
        ssize_t n = read(fd, &buf, sizeof(buf));
        close(fd);
        if (n != -1) {
            buf[n] = '\x00';
            return (g_flag = strdup(buf));
        }
    }
    return NULL;
}

uint32_t randint() {
    static int fd;
    if (!fd) {
        fd = open("/dev/urandom", O_RDONLY);
    }
    uint32_t r = 0;
    read(fd, &r, sizeof(r));
    return r;
}

size_t bin2hex(const char *src, char *dst, size_t len) {
    const char *hexchars = "0123456789abcdef";
    int j = 0;
    for (int i = 0; i < len; i++) {
        uint8_t c = src[i];
        dst[j++] = hexchars[c >> 4];
        dst[j++] = hexchars[c & 0xf];
    }
    return j;
}

static inline uint8_t h2d(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return 0;
}

size_t hex2bin(const char *src, char *dst, size_t len) {
    int j = 0;
    for (int i = 0; i < len; i += 2) {
        uint8_t c = (h2d(src[i]) << 4) | (h2d(src[i + 1]));
        dst[j++] = c;
    }
    return j;
}

struct json_value_s *nextjson(struct client *client) {
    char *buf = client->buf;

    while (!strchr(buf, '}') && client->buf_len < CLIENT_BUFSIZE - 1) {
        ssize_t len = read(0, &buf[client->buf_len], CLIENT_BUFSIZE - 1 - client->buf_len);
        if (len <= 0) {
            return NULL;
        }
        client->last_read = time(NULL);
        client->total_read += len;

        client->buf_len += len;
        buf[client->buf_len] = '\0';
    }

    char *start = strchr(buf, '{');
    if (start == NULL) {
        return NULL;
    }

    int c = 0;
    char *end = &buf[client->buf_len];
    for (char *s = start; s < end; s++) {
        if (*s == '{') {
            c++;
        } else if (*s == '}') {
            if (--c == 0) {
                char t = *++s;
                *s = '\0';

                int len = strlen(start);
                struct json_value_s *obj = json_parse(start, len);

                *s = t;
                client->buf_len = end - s;
                memmove(buf, s, client->buf_len + 1); // including the NULL byte
                return obj; // valid or NULL
            }
        }
    }
    // no valid json
    return NULL;
}
