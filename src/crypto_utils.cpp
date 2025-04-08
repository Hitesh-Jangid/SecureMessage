#include "crypto_utils.h"
#include "message_format.h" // For hexEncode/hexDecode if needed for debugging
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>

namespace CryptoUtils {

bool aesEncrypt(const std::string &plaintext, const std::string &key, std::string &ciphertext, std::string &iv) {
    const int AES_BLOCK_SIZE = 16;
    iv.resize(AES_BLOCK_SIZE, '\0');
    if (!RAND_bytes(reinterpret_cast<unsigned char*>(&iv[0]), AES_BLOCK_SIZE)) {
        std::cerr << "[CryptoUtils] Error generating IV\n";
        return false;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[CryptoUtils] Error creating EVP context\n";
        return false;
    }
    const EVP_CIPHER *cipher = nullptr;
    if (key.size() == 16)
        cipher = EVP_aes_128_cbc();
    else if (key.size() == 32)
        cipher = EVP_aes_256_cbc();
    else {
        std::cerr << "[CryptoUtils] Unsupported AES key size\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL,
                                reinterpret_cast<const unsigned char*>(key.data()),
                                reinterpret_cast<const unsigned char*>(iv.data()))) {
        std::cerr << "[CryptoUtils] Error initializing AES encryption\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    std::vector<unsigned char> outbuf(plaintext.size() + AES_BLOCK_SIZE);
    int outlen = 0, tmplen = 0;
    if (1 != EVP_EncryptUpdate(ctx, outbuf.data(), &outlen,
                               reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size())) {
        std::cerr << "[CryptoUtils] Error during AES encryption update\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (1 != EVP_EncryptFinal_ex(ctx, outbuf.data() + outlen, &tmplen)) {
        std::cerr << "[CryptoUtils] Error during AES encryption finalization\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outlen += tmplen;
    ciphertext.assign(reinterpret_cast<char*>(outbuf.data()), outlen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aesDecrypt(const std::string &ciphertext, const std::string &key, const std::string &iv, std::string &plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[CryptoUtils] Error creating EVP context for decryption\n";
        return false;
    }
    const EVP_CIPHER *cipher = nullptr;
    if (key.size() == 16)
        cipher = EVP_aes_128_cbc();
    else if (key.size() == 32)
        cipher = EVP_aes_256_cbc();
    else {
        std::cerr << "[CryptoUtils] Unsupported AES key size\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL,
                                reinterpret_cast<const unsigned char*>(key.data()),
                                reinterpret_cast<const unsigned char*>(iv.data()))) {
        std::cerr << "[CryptoUtils] Error initializing AES decryption\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    std::vector<unsigned char> outbuf(ciphertext.size() + 16);
    int outlen = 0, tmplen = 0;
    if (1 != EVP_DecryptUpdate(ctx, outbuf.data(), &outlen,
                               reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size())) {
        std::cerr << "[CryptoUtils] Error during AES decryption update\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (1 != EVP_DecryptFinal_ex(ctx, outbuf.data() + outlen, &tmplen)) {
        std::cerr << "[CryptoUtils] Error during AES decryption finalization (wrong key/IV?)\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outlen += tmplen;
    plaintext.assign(reinterpret_cast<char*>(outbuf.data()), outlen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool rsaEncryptAESKey(const std::string &aesKey, RSA *rsa, std::string &encryptedKey) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        std::cerr << "[CryptoUtils] Error creating EVP_PKEY structure\n";
        return false;
    }
    if (EVP_PKEY_set1_RSA(pkey, rsa) <= 0) {
        std::cerr << "[CryptoUtils] Error setting RSA key into EVP_PKEY\n";
        EVP_PKEY_free(pkey);
        return false;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cerr << "[CryptoUtils] Error creating EVP_PKEY_CTX\n";
        EVP_PKEY_free(pkey);
        return false;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cerr << "[CryptoUtils] Error initializing encryption context\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "[CryptoUtils] Error setting RSA OAEP padding\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, reinterpret_cast<const unsigned char*>(aesKey.data()), aesKey.size()) <= 0) {
        std::cerr << "[CryptoUtils] Error obtaining encrypted length\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    std::vector<unsigned char> buffer(outlen);
    if (EVP_PKEY_encrypt(ctx, buffer.data(), &outlen, reinterpret_cast<const unsigned char*>(aesKey.data()), aesKey.size()) <= 0) {
        std::cerr << "[CryptoUtils] RSA encryption of AES key failed\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    encryptedKey.assign(reinterpret_cast<char*>(buffer.data()), outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return true;
}

bool rsaDecryptAESKey(const std::string &encryptedKey, RSA *rsa, std::string &aesKey) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        std::cerr << "[CryptoUtils] Error creating EVP_PKEY structure\n";
        return false;
    }
    if (EVP_PKEY_set1_RSA(pkey, rsa) <= 0) {
        std::cerr << "[CryptoUtils] Error setting RSA key into EVP_PKEY\n";
        EVP_PKEY_free(pkey);
        return false;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        std::cerr << "[CryptoUtils] Error creating EVP_PKEY_CTX\n";
        EVP_PKEY_free(pkey);
        return false;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        std::cerr << "[CryptoUtils] Error initializing decryption context\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "[CryptoUtils] Error setting RSA OAEP padding\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, reinterpret_cast<const unsigned char*>(encryptedKey.data()), encryptedKey.size()) <= 0) {
        std::cerr << "[CryptoUtils] Error obtaining decrypted length\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    std::vector<unsigned char> buffer(outlen);
    if (EVP_PKEY_decrypt(ctx, buffer.data(), &outlen, reinterpret_cast<const unsigned char*>(encryptedKey.data()), encryptedKey.size()) <= 0) {
        std::cerr << "[CryptoUtils] RSA decryption of AES key failed\n";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    aesKey.assign(reinterpret_cast<char*>(buffer.data()), outlen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return true;
}

// Sign the message (which in our case is the encrypted payload) using RSA private key.
// The signature is returned in a vector of unsigned char.
bool signMessage(const std::string &message, RSA *privateKey, std::vector<unsigned char> &signature) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "[CryptoUtils] Error creating MD context for signing\n";
        return false;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_set1_RSA(pkey, privateKey) <= 0) {
        std::cerr << "[CryptoUtils] Error setting RSA private key\n";
        if (pkey) EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        std::cerr << "[CryptoUtils] Error initializing digest sign\n";
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    if (EVP_DigestSignUpdate(mdctx, message.data(), message.size()) != 1) {
        std::cerr << "[CryptoUtils] Error updating digest sign\n";
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    size_t sigLen = 0;
    if (EVP_DigestSignFinal(mdctx, NULL, &sigLen) != 1) {
        std::cerr << "[CryptoUtils] Error obtaining signature length\n";
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    signature.resize(sigLen);
    if (EVP_DigestSignFinal(mdctx, signature.data(), &sigLen) != 1) {
        std::cerr << "[CryptoUtils] Error finalizing signature\n";
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    signature.resize(sigLen);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    return true;
}

// Verify the signature using RSA public key.
// The signature is provided as a vector of unsigned char.
bool verifySignature(const std::string &message, const std::vector<unsigned char> &signature, RSA *publicKey) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "[CryptoUtils] Error creating MD context for verification\n";
        return false;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_set1_RSA(pkey, publicKey) <= 0) {
        std::cerr << "[CryptoUtils] Error setting RSA public key\n";
        if (pkey) EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        std::cerr << "[CryptoUtils] Error initializing digest verify\n";
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    if (EVP_DigestVerifyUpdate(mdctx, message.data(), message.size()) != 1) {
        std::cerr << "[CryptoUtils] Error updating digest verify\n";
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    int ret = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    if (ret == 1)
        return true;
    else if (ret == 0) {
        std::cerr << "[CryptoUtils] Signature verification failed (Invalid Signature)\n";
        return false;
    } else {
        std::cerr << "[CryptoUtils] Error verifying signature\n";
        return false;
    }
}

} // namespace CryptoUtils
