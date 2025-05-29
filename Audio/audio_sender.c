#include "audio_lib.h"
#include "aes.h"
#include <alsa/asoundlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define SAMPLE_RATE 44100
#define CHANNELS 1
#define FORMAT SND_PCM_FORMAT_S16_LE
#define FRAME_SIZE 2
#define BUFFER_SIZE 256
#define FRAMES (BUFFER_SIZE / FRAME_SIZE)

void start_audio_sender(const char* ip, int port, const uint8_t* key, const uint8_t* iv) {
    snd_pcm_t *handle;
    snd_pcm_hw_params_t *params;
    int dir;
    unsigned int rate = SAMPLE_RATE;

    printf("[AudioSender] Initializing ALSA for %dHz mono 16-bit...\n", SAMPLE_RATE);
    if (snd_pcm_open(&handle, "default", SND_PCM_STREAM_CAPTURE, 0) < 0) {
        perror("[AudioSender] Failed to open PCM device");
        return;
    }

    snd_pcm_hw_params_malloc(&params);
    snd_pcm_hw_params_any(handle, params);
    snd_pcm_hw_params_set_access(handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);
    snd_pcm_hw_params_set_format(handle, params, FORMAT);
    snd_pcm_hw_params_set_channels(handle, params, CHANNELS);
    snd_pcm_hw_params_set_rate_near(handle, params, &rate, &dir);
    snd_pcm_hw_params(handle, params);
    snd_pcm_hw_params_free(params);
    snd_pcm_prepare(handle);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serv_addr.sin_addr);

    printf("[AudioSender] Connecting to %s:%d...\n", ip, port);
    while (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("[AudioSender] Waiting for receiver...");
        sleep(1);
    }
    printf("[AudioSender] Connected to receiver.\n");

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);

    char buffer[BUFFER_SIZE];
    while (1) {
        int frames = snd_pcm_readi(handle, buffer, FRAMES);
        if (frames < 0) {
            frames = snd_pcm_recover(handle, frames, 0);
            if (frames < 0) {
                fprintf(stderr, "[AudioSender] Read error: %s\n", snd_strerror(frames));
                break;
            }
        }
        // === Timing encryption ===
        struct timespec start, end;

clock_gettime(CLOCK_MONOTONIC, &start);
AES_CTR_xcrypt_buffer(&ctx, (uint8_t*)buffer, frames * FRAME_SIZE);
clock_gettime(CLOCK_MONOTONIC, &end);

double elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 +
                    (end.tv_nsec - start.tv_nsec) / 1e6;

printf("[AudioSender] Encrypted %d bytes in %.3f ms\n", frames * FRAME_SIZE, elapsed_ms);
        send(sockfd, buffer, frames * FRAME_SIZE, 0);
    }

    snd_pcm_close(handle);
    close(sockfd);
}
