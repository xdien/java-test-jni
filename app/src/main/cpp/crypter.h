// Copyright 2015 Sergey Frolov. All rights reserved.
// Use of this source code is governed by a LGPL license that can be
// found in the LICENSE file.

#ifndef DFS_SSL_CRYPTER_H
#define DFS_SSL_CRYPTER_H

#include <string>
class evp_cipher_ctx_st;

using std::string;

class AESCrypter {
private:
    unsigned char key[32];
    unsigned char iv[32];
    evp_cipher_ctx_st *encrypt_ctx;
    evp_cipher_ctx_st *decrypt_ctx;

    void construct();
    static AESCrypter *m_intance;

public:
    AESCrypter(const char *seed, int num);
    AESCrypter(unsigned char input_key[32], unsigned char input_iv[32]);

    std::string encrypt(const std::string &input);
    std::string decrypt(const std::string &input);

    unsigned char *encrypt(const unsigned char *input, const int *input_len, int *output_len);
    unsigned char *decrypt(const unsigned char *input, const int *input_len, int *output_len);

    ~AESCrypter();
    static AESCrypter *intance();
};

#endif //DFS_SSL_CRYPTER_H
