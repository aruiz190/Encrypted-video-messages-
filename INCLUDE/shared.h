#ifndef SHARED_H
#define SHARED_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MSG_TYPE_LEN 16
#define MAX_PAYLOAD 65536

typedef struct {
    char type[MSG_TYPE_LEN];   // "TEXT", "CALL_REQUEST", etc.
    uint32_t length;           // payload size in bytes
} MessageHeader;

int send_message(int sockfd, const char *type, const void *data, uint32_t len);
int recv_message(int sockfd, char *type_out, void *buffer, uint32_t *len_out);

#ifdef __cplusplus
}
#endif

#endif
