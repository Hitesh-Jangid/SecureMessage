#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include <string>
#include <openssl/rsa.h>

namespace KeyManager {
    // Generate an RSA key pair and save to the specified files.
    bool generateRSAKeyPair(const std::string &publicKeyFile, const std::string &privateKeyFile, int keySize = 2048);
    // Load an RSA public key from a PEM file.
    RSA* loadPublicKey(const std::string &publicKeyFile);
    // Load an RSA private key from a PEM file.
    RSA* loadPrivateKey(const std::string &privateKeyFile);
}

#endif // KEY_MANAGER_H
