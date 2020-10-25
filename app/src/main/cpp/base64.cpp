#include "base64.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <math.h>
#include <string.h>

char* base64Encode(const unsigned char *message, const size_t length) {
  int encodedSize = 4 * ceil((double)length / 3);
  char *b64text = (char*)malloc(encodedSize + 1);

  if(b64text == nullptr) {
    fprintf(stderr, "Failed to allocate memory\n");
    exit(1);
  }
  if(length == 0)
      return  b64text;

  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  BIO_write(bio, message, length);
  BIO_flush(bio);

  BUF_MEM *bufferPtr;
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_CLOSE);

  memcpy(b64text, (*bufferPtr).data, (*bufferPtr).length + 1);
  b64text[(*bufferPtr).length] = '\0';

  BIO_free_all(bio);
  return b64text;
}

int base64Decode(const char *b64message, const size_t length, unsigned char **buffer) {
    BIO *bio, *b64;
        int decodeLen = calcDecodeLength(b64message);
        *buffer = (unsigned char*)malloc(decodeLen + 1);
        (*buffer)[decodeLen] = '\0';

        bio = BIO_new_mem_buf(b64message, -1);
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
        BIO_read(bio, *buffer, strlen(b64message));
//        assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
        BIO_free_all(bio);

        return (0); //success

}

int calcDecodeLength(const char *b64input) {
    size_t len = strlen(b64input),
            padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    return (len*3)/4 - padding;
}
