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
#include <pthread.h>


void* handle_client(void* arg); 


#define PORT 9000
#define MAX_CLIENTS 10
#define USERNAME_LEN 32

typedef struct {
    int sockfd;
    char username[USERNAME_LEN];
    pthread_t thread;
} Client;


Client clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

void add_client(int sockfd, const char* username) {
    pthread_mutex_lock(&clients_mutex);
    if (client_count < MAX_CLIENTS) {
        clients[client_count].sockfd = sockfd;
        strncpy(clients[client_count].username, username, USERNAME_LEN - 1);
        clients[client_count].username[USERNAME_LEN - 1] = '\0';
        client_count++;
    }
    pthread_mutex_unlock(&clients_mutex);
}

int get_client_fd(const char* username) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (strcmp(clients[i].username, username) == 0) {
            pthread_mutex_unlock(&clients_mutex);
            return clients[i].sockfd;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return -1; 
}



pthread_t video_send_thread;
pthread_t video_recv_thread;
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
    int client_pub_len;
    if (recv(sockfd, &client_pub_len, sizeof(int), 0) <= 0) {
        fprintf(stderr, "[!] Failed to receive client DH pub key length.\n");
        return;
    }
    printf("[DEBUG] Received client DH pub key length = %d\n", client_pub_len);

    unsigned char *client_pub_buf = malloc(client_pub_len);
    if (recv(sockfd, client_pub_buf, client_pub_len, 0) <= 0) {
        fprintf(stderr, "[!] Failed to receive client DH pub key data.\n");
        free(client_pub_buf);
        return;
    }
    printf("[DEBUG] Received client DH pub key\n");

    BIGNUM *client_pub_key = BN_bin2bn(client_pub_buf, client_pub_len, NULL);
    free(client_pub_buf);

    DH *dh = DH_get_2048_256();
    if (!dh || !DH_generate_key(dh)) {
        fprintf(stderr, "[!] Failed to generate server DH key.\n");
        return;
    }

    const BIGNUM *server_pub_key = NULL;
    DH_get0_key(dh, &server_pub_key, NULL);

    int server_pub_len = BN_num_bytes(server_pub_key);
    unsigned char *server_pub_buf = malloc(server_pub_len);
    BN_bn2bin(server_pub_key, server_pub_buf);

    send(sockfd, &server_pub_len, sizeof(int), 0);
    send(sockfd, server_pub_buf, server_pub_len, 0);
    printf("[DEBUG] Sent server DH pub key\n");

    int secret_size = DH_size(dh);
    unsigned char *secret = malloc(secret_size);
    secret_size = DH_compute_key(secret, client_pub_key, dh);
    printf("[DEBUG] Shared secret computed. Size = %d\n", secret_size);

    derive_key_iv(secret, secret_size);

    BN_free(client_pub_key);
    free(server_pub_buf);
    free(secret);
    DH_free(dh);
}

void* recv_loop(void* arg) {
    int sockfd = *(int*)arg;
    char type[MSG_TYPE_LEN];
    char buffer[MAX_PAYLOAD];
    uint32_t len;

    char username[USERNAME_LEN] = "";

    while (1) {
        if (recv_message(sockfd, type, buffer, &len) < 0) {
            printf("[!] Connection closed or error.\n");
            break;
        }
        buffer[len] = '\0';

        
        if (strcmp(type, "USERNAME") == 0) {
            strncpy(username, buffer, USERNAME_LEN - 1);
            username[USERNAME_LEN - 1] = '\0';
            add_client(sockfd, username);
            printf("[Server] Registered client username: %s\n", username);
            continue;
        }

        if (strcmp(type, "TEXT") == 0) {
            char* colon = strchr(buffer, ':');
            if (!colon) {
                printf("[Server] Invalid TEXT format. Use target:message\n");
                continue;
            }

            *colon = '\0';
            const char* target_user = buffer;
            const char* actual_msg = colon + 1;

            int target_fd = get_client_fd(target_user);
             if (target_fd >= 0) {
             char full_msg[MAX_PAYLOAD];
             snprintf(full_msg, sizeof(full_msg), "[%s]: %s", username, actual_msg);
             send_message(target_fd, "TEXT", full_msg, strlen(full_msg));
           } else {
               printf("[Server] User %s not found.\n", target_user);
           }

        } else if (strcmp(type, "CALL_REQUEST") == 0) {
            int target_fd = get_client_fd(buffer);
            if (target_fd >= 0) {
                send_message(target_fd, "CALL_REQUEST", NULL, 0);
            }

        } else if (strcmp(type, "CALL_ACCEPT") == 0) {
            send_message(sockfd, "CALL_ACCEPT", NULL, 0);

        } else if (strcmp(type, "CALL_REJECT") == 0) {
            send_message(sockfd, "CALL_REJECT", NULL, 0);

        } else if (strcmp(type, "CALL_END") == 0) {
            send_message(sockfd, "CALL_END", NULL, 0);

        } else if (strcmp(type, "WHO") == 0) {
            pthread_mutex_lock(&clients_mutex);
            char list[MAX_PAYLOAD] = "";
            for (int i = 0; i < client_count; i++) {
                strcat(list, clients[i].username);
                if (i != client_count - 1) strcat(list, ", ");
            }
            pthread_mutex_unlock(&clients_mutex);
            send_message(sockfd, "TEXT", list, strlen(list));
        }
    }

    return NULL;
}



void* send_loop(void* arg) {
    int sockfd = *(int*)arg;
    char input[MAX_PAYLOAD];

    while (1) {
        printf("Enter message ('call', 'end', 'accept', 'reject'): ");
        if (fgets(input, sizeof(input), stdin) == NULL) break;
        input[strcspn(input, "\n")] = 0;

        if (strcmp(input, "call") == 0) {
            send_message(sockfd, "CALL_REQUEST", NULL, 0);
        } else if (strcmp(input, "accept") == 0 && call_pending) {
            send_message(sockfd, "CALL_ACCEPT", NULL, 0);
            in_call = 1;
            call_pending = 0;
            printf("Accepted call. Starting video...\n");
            system("python3 src/video_call.py &");
        } else if (strcmp(input, "reject") == 0 && call_pending) {
            send_message(sockfd, "CALL_REJECT", NULL, 0);
            call_pending = 0;
        } else if (strcmp(input, "end") == 0 && in_call) {
            send_message(sockfd, "CALL_END", NULL, 0);
            in_call = 0;
            system("pkill -F /tmp/video_call.pid");
            sleep(1);
        } else {
            send_message(sockfd, "TEXT", input, strlen(input));
        }
    }
    return NULL;
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);  
    printf("[Server] Waiting for connection on port %d...\n", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int* client_fd = malloc(sizeof(int)); 
        *client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (*client_fd < 0) {
            perror("accept");
            free(client_fd);
            continue;
        }

        printf("[Server] Client connected from %s\n", inet_ntoa(client_addr.sin_addr));

        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, handle_client, client_fd) != 0) {
            perror("pthread_create");
            close(*client_fd);
            free(client_fd);
            continue;
        }

        pthread_detach(client_thread); 
    }

    close(server_fd);
    return 0;
}

void* handle_client(void* arg) {
    int client_fd = *(int*)arg;
    free(arg);  

    printf("[Thread] Starting DH key exchange...\n");
    perform_dh_key_exchange(client_fd);
    printf("[Thread] DH key exchange complete.\n");

    printf("[Thread] Environment setup:\n");
    printf("  AES_KEY = %s\n", getenv("AES_KEY"));
    printf("  AES_IV  = %s\n", getenv("AES_IV"));

    recv_loop(&client_fd);

    return NULL;
}
