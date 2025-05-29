#include "shared.h"
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>

int send_message(int sockfd, const char *type, const void *data, uint32_t len) {
    printf("[DEBUG] send_message called:\n");
    printf("  type   = %s\n", type);
    printf("  length = %u\n", len);
    if (data) {
        printf("  data   = %.*s\n", len, (const char*)data);
    } else {
        printf("  data   = (null)\n");
    }

    MessageHeader header;
    memset(&header, 0, sizeof(header));
    strncpy(header.type, type, MSG_TYPE_LEN - 1);
    header.length = htonl(len);

    if (write(sockfd, &header, sizeof(header)) != sizeof(header)) return -1;
    if (len > 0 && write(sockfd, data, len) != (ssize_t)len) return -1;
    return 0;
}

int recv_message(int sockfd, char *type_out, void *buffer, uint32_t *len_out) {
    MessageHeader header;
    ssize_t n = read(sockfd, &header, sizeof(header));
    if (n <= 0) return -1;

    strncpy(type_out, header.type, MSG_TYPE_LEN);
    *len_out = ntohl(header.length);

    printf("[recv_message] Received header:\n");
    printf("  type   = %s\n", type_out);
    printf("  length = %u\n", *len_out);

    if (*len_out > 0) {
        n = read(sockfd, buffer, *len_out);
        if (n <= 0) return -1;

        printf("[recv_message] Payload = %.*s\n", *len_out, (char*)buffer);
    }

    return 0;
}
