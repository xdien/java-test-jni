
#include "crypter.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/opensslv.h>
#include <random>
#include <openssl/ssl.h>

#include "base64.h"
#include "jni.h"
AESCrypter *AESCrypter::m_intance =nullptr;
AESCrypter::AESCrypter(unsigned char input_key[32], unsigned char input_iv[32]) {
    for (int i = 0; i < 32; i++) {
        key[i] = input_key[i];
    }
    for (int i = 0; i < 32; i++) {
        iv[i] = input_iv[i];
    }
    construct();
}

AESCrypter::AESCrypter(const char *seed, int num) {
    std::seed_seq seq_seed(seed, seed + num);

    std::default_random_engine rng(seq_seed);
    std::uniform_int_distribution<int> rng_dist(0, 255);
    for (int i = 0; i < 32; i++) {
        key[i] = static_cast<unsigned char>(rng_dist(rng));
    }
    for (int i = 0; i < 32; i++) {
        iv[i] = static_cast<unsigned char>(rng_dist(rng));
    }
    construct();
}

void AESCrypter::construct() {

    encrypt_ctx = EVP_CIPHER_CTX_new() ;
    decrypt_ctx = EVP_CIPHER_CTX_new() ;
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
//    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr);
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms(); // should be called after init
#else
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(nullptr);
#endif

    if (!EVP_EncryptInit(encrypt_ctx, EVP_aes_192_ofb(), key, iv)) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("AEScrypter: &encrypt_ctx EVP_EncryptInit failed!");
    }

    if (!EVP_DecryptInit(decrypt_ctx, EVP_aes_192_ofb(), key, iv)) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("AEScrypter: &decrypt_ctx EVP_DecryptInit failed!");
    }
}

AESCrypter *AESCrypter::intance()
{
    if(AESCrypter::m_intance ==nullptr){
        std::string seed = "key this is key key @#!$%%";
        AESCrypter::m_intance = new AESCrypter(seed.data(),seed.size());
    }
    return AESCrypter::m_intance;
}



string AESCrypter::encrypt(const string &input) {
    int output_size;
    int input_size = input.size();
    unsigned char *output_uchar;

    output_uchar = encrypt( (unsigned char*) input.c_str(), &(input_size), &(output_size));

    string output(output_uchar, output_uchar + output_size);
    return  output;
}

string AESCrypter::decrypt(const string &input) {
//    auto msg = (unsigned char *) input.toStdString().c_str();
    int output_size;

    unsigned char *output_uchar;
    unsigned char *input_uchar_ptr ;//= (unsigned char *) input.toStdString().c_str();
    base64Decode(input.c_str(),input.length(),&input_uchar_ptr);
//    input_uchar_ptr = reinterpret_cast<unsigned char*>(input.toUtf8().toBase64().data());
//    std::string src = base64::from_base64(input.toStdString().c_str());
//    input_uchar_ptr = reinterpret_cast<unsigned char*>(const_cast<char*>(src.c_str()));
    int input_size = strlen((char*)input_uchar_ptr);
//    qInfo() << "dp dai input " << input_size<<input_uchar_ptr;
    output_uchar = decrypt(input_uchar_ptr, &(input_size), &(output_size));
    int doDaistrle = strlen((char *) output_uchar);
    if( doDaistrle<=0){

//        return QStringLiteral("");
        return  "";
    }else {
        string output(output_uchar, output_uchar + output_size);
        return  output;
//        return QString::fromStdString(output);
    }

}

unsigned char *AESCrypter::encrypt(const unsigned char *input, const int *input_len, int *output_len) {
    int encrypted_text_len = 0;
    int encrypted_text_pad_len = 0;;

    unsigned char *encrypted_text;
    encrypted_text = new unsigned char[*input_len + AES_BLOCK_SIZE];
    memset(encrypted_text, 0, *input_len + AES_BLOCK_SIZE);

    if(1 != EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_192_ofb(), nullptr, key, iv)){
//            qCritical() << "AESCrypter: crypt(): EVP_EncryptInit_ex() failed!";
    }

//    EVP_CIPHER_CTX_set_padding(&encrypt_ctx,0);
    if (!EVP_EncryptUpdate(encrypt_ctx, encrypted_text, &encrypted_text_len, input, *input_len)) {
//        qCritical() << "AESCrypter: crypt(): EVP_EncryptUpdate() failed!";
        delete[] encrypted_text;
        throw std::runtime_error("AESCrypter: crypt(): EVP_CipherUpdate() failed!");
    }

    if (!EVP_EncryptFinal_ex(encrypt_ctx, encrypted_text + encrypted_text_len, &encrypted_text_pad_len)) {
//        qCritical() << "AESCrypter: crypt(): EVP_CipherFinal_ex() failed!";
        delete[] encrypted_text;
        throw std::runtime_error("AESCrypter: crypt(): EVP_CipherFinal_ex() failed!");
    }

    if (output_len != nullptr)
        *output_len = encrypted_text_len + encrypted_text_pad_len;
    else{
//        qCritical() << "AESCrypter: crypt(): output_len is nullptr!";
        throw std::runtime_error("AESCrypter: crypt(): output_len is nullptr!");
    }

    return encrypted_text;
}

unsigned char *AESCrypter::decrypt(const unsigned char *input, const int *input_len, int *output_len) {
    int decrypted_text_len = 0;
    int decrypted_text_pad_len = 0;;

    unsigned char *decrypted_text;
    decrypted_text = new unsigned char[*input_len];
    memset(decrypted_text, 0, *input_len);
    if(1 != EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_192_ofb(), nullptr, key, iv)){
        //            qCritical() <<" EVP_DecryptInit_ex failed!" ;
    }

    EVP_CIPHER_CTX_set_padding(decrypt_ctx,0);
    if (!EVP_DecryptUpdate(decrypt_ctx, decrypted_text, &decrypted_text_len, input, *input_len)) {
        ERR_print_errors_fp(stderr);
        delete[] decrypted_text;
        throw std::runtime_error("AESCrypter: decrypt(): EVP_DecryptUpdate() failed!");
    }

    if (!EVP_DecryptFinal_ex(decrypt_ctx, decrypted_text + decrypted_text_len, &decrypted_text_pad_len)) {
        ERR_print_errors_fp(stderr);
        decrypted_text[0]='\0';
//        throw std::runtime_error("AESCrypter: decrypt(): EVP_DecryptFinal_ex() failed!");
        return  decrypted_text;
    }

    if (output_len != nullptr)
        *output_len = decrypted_text_len + decrypted_text_pad_len;
    else
        throw std::runtime_error("AESCrypter: crypt(): output_len is nullptr!");

    return decrypted_text;
}


AESCrypter::~AESCrypter() {
    EVP_CIPHER_CTX_cleanup(encrypt_ctx);
    EVP_CIPHER_CTX_cleanup(decrypt_ctx);
    EVP_CIPHER_CTX_free(decrypt_ctx);
    EVP_CIPHER_CTX_free(encrypt_ctx);
    EVP_cleanup();
    ERR_free_strings();
}


extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_myapplication_MainActivity_stringFromJNI(JNIEnv *env, jclass clazz,
                                                          jstring input) {
    const char *plaintext = env->GetStringUTFChars(input,0);
    std::string strInput(plaintext);
    std::string  output = AESCrypter::intance()->encrypt(strInput);
    return env->NewStringUTF(base64Encode((unsigned char * )output.c_str(),output.size()));
}