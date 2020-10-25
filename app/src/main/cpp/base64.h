#ifndef BASE64_H
#define BASE64_H


#include <stdio.h>

char* base64Encode(const unsigned char *buffer, const size_t length);
int base64Decode(const char *b64message, const size_t length, unsigned char **buffer);
int calcDecodeLength(const char *b64input);

#endif
