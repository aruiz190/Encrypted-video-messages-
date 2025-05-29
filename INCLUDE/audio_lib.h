#ifndef AUDIO_LIB_H
#define AUDIO_LIB_H

#include <stdint.h>  // Needed for uint8_t

#ifdef __cplusplus
extern "C" {
#endif

void start_audio_sender(const char* ip, int port, const uint8_t* key, const uint8_t* iv);
void start_audio_receiver(int port, const uint8_t* key, const uint8_t* iv);
void hex_to_bytes(const char *hex, uint8_t *out, int len);

#ifdef __cplusplus
}
#endif

#endif // AUDIO_LIB_H
