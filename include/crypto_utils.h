#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <vector>
#include <openssl/rsa.h>

namespace CryptoUtils {
    // AES encryption/decryption using CBC mode.
    bool aesEncrypt(const std::string &plaintext, const std::string &key, std::string &ciphertext, std::string &iv);
    bool aesDecrypt(const std::string &ciphertext, const std::string &key, const std::string &iv, std::string &plaintext);

    // RSA encryption (wrapping) and decryption (unwrapping) of an AES key using OAEP padding.
    bool rsaEncryptAESKey(const std::string &aesKey, RSA *rsa, std::string &encryptedKey);
    bool rsaDecryptAESKey(const std::string &encryptedKey, RSA *rsa, std::string &aesKey);

    // Digital signature functions using RSA with SHA-256.
    // The signature is returned in a vector to avoid string issues.
    bool signMessage(const std::string &message, RSA *privateKey, std::vector<unsigned char> &signature);
    bool verifySignature(const std::string &message, const std::vector<unsigned char> &signature, RSA *publicKey);
}

#endif // CRYPTO_UTILS_H
