#include "key_manager.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <iostream>

namespace KeyManager {

bool generateRSAKeyPair(const std::string &publicKeyFile, const std::string &privateKeyFile, int keySize) {
    bool success = false;
    RSA *rsa = nullptr;
    BIGNUM *bne = nullptr;
    FILE *privFile = nullptr, *pubFile = nullptr;

    rsa = RSA_new();
    if (!rsa) {
        std::cerr << "[KeyManager] RSA_new() failed\n";
        goto cleanup;
    }
    bne = BN_new();
    if (!bne) {
        std::cerr << "[KeyManager] BN_new() failed\n";
        goto cleanup;
    }
    if (!BN_set_word(bne, RSA_F4)) {
        std::cerr << "[KeyManager] Error setting RSA exponent\n";
        goto cleanup;
    }
    if (!RSA_generate_key_ex(rsa, keySize, bne, NULL)) {
        std::cerr << "[KeyManager] RSA key generation failed\n";
        goto cleanup;
    }
    privFile = fopen(privateKeyFile.c_str(), "wb");
    if (!privFile) {
        std::cerr << "[KeyManager] Unable to open file for private key: " << privateKeyFile << "\n";
        goto cleanup;
    }
    if (!PEM_write_RSAPrivateKey(privFile, rsa, NULL, NULL, 0, NULL, NULL)) {
        std::cerr << "[KeyManager] Error writing private key\n";
        goto cleanup;
    }
    fclose(privFile);
    privFile = nullptr;
    
    pubFile = fopen(publicKeyFile.c_str(), "wb");
    if (!pubFile) {
        std::cerr << "[KeyManager] Unable to open file for public key: " << publicKeyFile << "\n";
        goto cleanup;
    }
    if (!PEM_write_RSA_PUBKEY(pubFile, rsa)) {
        std::cerr << "[KeyManager] Error writing public key\n";
        goto cleanup;
    }
    fclose(pubFile);
    pubFile = nullptr;
    
    success = true;
    
cleanup:
    if (bne) BN_free(bne);
    if (rsa) RSA_free(rsa);
    if (privFile) fclose(privFile);
    if (pubFile) fclose(pubFile);
    return success;
}

RSA* loadPublicKey(const std::string &publicKeyFile) {
    FILE *fp = fopen(publicKeyFile.c_str(), "rb");
    if (!fp) {
        std::cerr << "[KeyManager] Unable to open public key file: " << publicKeyFile << "\n";
        return nullptr;
    }
    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

RSA* loadPrivateKey(const std::string &privateKeyFile) {
    FILE *fp = fopen(privateKeyFile.c_str(), "rb");
    if (!fp) {
        std::cerr << "[KeyManager] Unable to open private key file: " << privateKeyFile << "\n";
        return nullptr;
    }
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

} // namespace KeyManager
