#include "audio_lib.h"
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <alsa/asoundlib.h>
#include <time.h>

#define SAMPLE_RATE 44100
#define CHANNELS 1
#define FORMAT SND_PCM_FORMAT_S16_LE
#define FRAME_SIZE 2
#define BUFFER_SIZE 256
#define FRAMES (BUFFER_SIZE / FRAME_SIZE)

void start_audio_receiver(int port, const uint8_t* key, const uint8_t* iv) {
    int server_fd, client_fd;
    struct sockaddr_in addr = {0};
    socklen_t addrlen = sizeof(addr);
    char buffer[BUFFER_SIZE];

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);

    snd_pcm_t *handle;
    snd_pcm_hw_params_t *params;

    printf("[AudioReceiver] Initializing ALSA for %dHz mono 16-bit...\n", SAMPLE_RATE);
    if (snd_pcm_open(&handle, "default", SND_PCM_STREAM_PLAYBACK, 0) < 0) {
        perror("[AudioReceiver] Failed to open PCM device");
        return;
    }

    snd_pcm_hw_params_malloc(&params);
    snd_pcm_hw_params_any(handle, params);
    snd_pcm_hw_params_set_access(handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);
    snd_pcm_hw_params_set_format(handle, params, FORMAT);
    snd_pcm_hw_params_set_channels(handle, params, CHANNELS);
    snd_pcm_hw_params_set_rate(handle, params, SAMPLE_RATE, 0);
    snd_pcm_hw_params(handle, params);
    snd_pcm_hw_params_free(params);
    snd_pcm_prepare(handle);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 1);
    printf("[AudioReceiver] Waiting for sender on port %d...\n", port);
    client_fd = accept(server_fd, (struct sockaddr*)&addr, &addrlen);
    printf("[AudioReceiver] Sender connected.\n");

    while (1) {
    ssize_t bytes_received = recv(client_fd, buffer, BUFFER_SIZE, MSG_WAITALL);
    if (bytes_received <= 0) break;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    AES_CTR_xcrypt_buffer(&ctx, (uint8_t*)buffer, bytes_received);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;

    printf("[AudioReceiver] Decrypted %zd bytes in %.3f ms\n", bytes_received, elapsed_ms);

    snd_pcm_writei(handle, buffer, bytes_received / FRAME_SIZE);
}

    close(client_fd);
    close(server_fd);
    snd_pcm_drain(handle);
    snd_pcm_close(handle);
}
