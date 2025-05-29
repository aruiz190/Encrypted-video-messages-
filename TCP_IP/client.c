#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "shared.h"

#define PORT 9000
#define USERNAME_LEN 32



atomic_bool in_call = 0;
int call_pending = 0;

void derive_key_iv(unsigned char *shared_secret, int secret_size) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(shared_secret, secret_size, hash);

    char key_hex[33], iv_hex[33];
    for (int i = 0; i < 16; i++) sprintf(key_hex + i * 2, "%02x", hash[i]);
    for (int i = 0; i < 16; i++) sprintf(iv_hex + i * 2, "%02x", hash[i + 16]);

    key_hex[32] = '\0';
    iv_hex[32] = '\0';
    setenv("AES_KEY", key_hex, 1);
    setenv("AES_IV", iv_hex, 1);
}

void perform_dh_key_exchange(int sockfd) {
    printf("[DEBUG] Starting DH key exchange...\n");

    DH *dh = DH_get_2048_256();
    if (!dh || !DH_generate_key(dh)) {
        fprintf(stderr, "[!] DH setup failed.\n");
        exit(1);
    }

    const BIGNUM *pub_key = NULL;
    DH_get0_key(dh, &pub_key, NULL);
    int pub_len = BN_num_bytes(pub_key);
    printf("[DEBUG] Local DH pub key length = %d\n", pub_len);

    unsigned char *pub_buf = malloc(pub_len);
    if (!pub_buf) {
        fprintf(stderr, "[!] malloc failed for pub_buf\n");
        exit(1);
    }

    BN_bn2bin(pub_key, pub_buf);

    if (send(sockfd, &pub_len, sizeof(int), 0) <= 0) {
        fprintf(stderr, "[!] Failed to send pub_len\n");
        exit(1);
    }
    if (send(sockfd, pub_buf, pub_len, 0) <= 0) {
        fprintf(stderr, "[!] Failed to send pub_buf\n");
        exit(1);
    }
    printf("[DEBUG] Sent DH public key\n");

    int peer_len = 0;
    if (recv(sockfd, &peer_len, sizeof(int), 0) <= 0 || peer_len <= 0) {
        fprintf(stderr, "[!] Failed to receive peer_len\n");
        exit(1);
    }
    printf("[DEBUG] Peer DH pub key length = %d\n", peer_len);

    unsigned char *peer_buf = malloc(peer_len);
    if (!peer_buf) {
        fprintf(stderr, "[!] malloc failed for peer_buf\n");
        exit(1);
    }

    if (recv(sockfd, peer_buf, peer_len, 0) <= 0) {
        fprintf(stderr, "[!] Failed to receive peer_buf\n");
        exit(1);
    }
    printf("[DEBUG] Received peer DH public key\n");

    BIGNUM *peer_key = BN_bin2bn(peer_buf, peer_len, NULL);
    if (!peer_key) {
        fprintf(stderr, "[!] Failed to convert peer key to BIGNUM\n");
        exit(1);
    }

    int secret_size = DH_size(dh);
    unsigned char *secret = malloc(secret_size);
    if (!secret) {
        fprintf(stderr, "[!] malloc failed for secret\n");
        exit(1);
    }

    secret_size = DH_compute_key(secret, peer_key, dh);
    if (secret_size <= 0) {
        fprintf(stderr, "[!] Failed to compute shared secret\n");
        exit(1);
    }
    printf("[DEBUG] Shared secret computed. Size = %d\n", secret_size);

    derive_key_iv(secret, secret_size);

    BN_free(peer_key);
    free(pub_buf);
    free(peer_buf);
    free(secret);
    DH_free(dh);

    printf("[DEBUG] DH key exchange complete.\n");
}

void* recv_loop(void* arg) {
    int sockfd = *(int*)arg;
    char type[MSG_TYPE_LEN];
    char buffer[MAX_PAYLOAD];
    uint32_t len;

    while (1) {
        if (recv_message(sockfd, type, buffer, &len) < 0) {
            printf("[!] Connection closed or error.\n");
            break;
        }
        buffer[len] = '\0';

        if (strcmp(type, "TEXT") == 0) {
            printf("[Server]: %s\n", buffer);
        } else if (strcmp(type, "CALL_REQUEST") == 0) {
            printf("[Server]: Call requested. Type 'accept' or 'reject'.\n");
            call_pending = 1;
        } else if (strcmp(type, "CALL_ACCEPT") == 0) {
            in_call = 1;
            printf("[Server]: Call accepted. Starting video stream...\n");
            system("python3 VIDEO/video_call.py & echo $! > /tmp/video_call.pid");
        } else if (strcmp(type, "CALL_REJECT") == 0) {
            printf("[Server]: Call rejected.\n");
        } else if (strcmp(type, "CALL_END") == 0) {
            in_call = 0;
            printf("[Server]: Call ended.\n");
            system("pkill -F /tmp/video_call.pid");
            sleep(1);
        }
    }
    return NULL;
}

void* send_loop(void* arg) {
    int sockfd = *(int*)arg;
    char input[MAX_PAYLOAD];
    char target[USERNAME_LEN];

    while (1) {
        printf("Enter recipient username (or type 'call', 'end', 'accept', 'reject', 'who'): ");
        if (fgets(input, sizeof(input), stdin) == NULL) break;
        input[strcspn(input, "\n")] = 0;

        if (strcmp(input, "call") == 0) {
            printf("Enter username to call: ");
            fgets(target, sizeof(target), stdin);
            target[strcspn(target, "\n")] = 0;
            send_message(sockfd, "CALL_REQUEST", target, strlen(target));

        } else if (strcmp(input, "accept") == 0 && call_pending) {
            send_message(sockfd, "CALL_ACCEPT", NULL, 0);
            in_call = 1;
            call_pending = 0;
            printf("Accepted call. Starting video...\n");
            system("python3 VIDEO/video_call.py & echo $! > /tmp/video_call.pid");

        } else if (strcmp(input, "reject") == 0 && call_pending) {
            send_message(sockfd, "CALL_REJECT", NULL, 0);
            call_pending = 0;

        } else if (strcmp(input, "end") == 0 && in_call) {
            send_message(sockfd, "CALL_END", NULL, 0);
            in_call = 0;
            system("pkill -F /tmp/video_call.pid");
            sleep(1);

        } else if (strcmp(input, "who") == 0 || strcmp(input, "WHO") == 0) {
            send_message(sockfd, "WHO", NULL, 0);

        } else {
            printf("Enter recipient username: ");
            fgets(target, sizeof(target), stdin);
            target[strcspn(target, "\n")] = 0;

            char formatted[MAX_PAYLOAD + USERNAME_LEN + 2];
            snprintf(formatted, sizeof(formatted), "%s:%s", target, input);
            send_message(sockfd, "TEXT", formatted, strlen(formatted));
        }
    }
    return NULL;
}


int main(int argc, char *argv[]) {
    printf("[DEBUG] Entered main()\n");

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

    const char* SERVER_IP = argv[1];
    setenv("PARTNER_IP", SERVER_IP, 1);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[ERROR] socket()");
        return 1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("[ERROR] connect()");
        return 1;
    }


    printf("[Client] Connected to server.\n");

printf("[DEBUG] Starting DH key exchange...\n");
perform_dh_key_exchange(sockfd);
printf("[DEBUG] DH key exchange complete.\n");


char username[USERNAME_LEN] = {0}; 
printf("Enter your username: ");
if (fgets(username, sizeof(username), stdin) == NULL) {
    fprintf(stderr, "[ERROR] Failed to read username.\n");
    close(sockfd);
    return 1;
}
username[strcspn(username, "\n")] = '\0';

if (strlen(username) == 0) {
    fprintf(stderr, "[ERROR] Username is empty. Exiting.\n");
    close(sockfd);
    return 1;
}

printf("[DEBUG] Sending USERNAME = '%s'\n", username);
int sent = send_message(sockfd, "USERNAME", username, strlen(username));
printf("[DEBUG] send_message returned %d\n", sent);


    printf("[Client] Environment setup:\n");
    printf("  PARTNER_IP = %s\n", getenv("PARTNER_IP"));
    printf("  AES_KEY    = %s\n", getenv("AES_KEY"));
    printf("  AES_IV     = %s\n", getenv("AES_IV"));

    pthread_t send_thread, recv_thread;
    pthread_create(&recv_thread, NULL, recv_loop, &sockfd);
    pthread_create(&send_thread, NULL, send_loop, &sockfd);

    pthread_join(send_thread, NULL);
    pthread_join(recv_thread, NULL);

    close(sockfd);
    return 0;
}
