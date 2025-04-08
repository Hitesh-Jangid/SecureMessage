#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "network_comm.h"
#include "key_manager.h"
#include "crypto_utils.h"
#include "message_format.h"

// Utility function to generate a random AES key.
std::string generateRandomAESKey(size_t length) {
    std::string key;
    key.resize(length);
    if (!RAND_bytes(reinterpret_cast<unsigned char*>(&key[0]), length)) {
        std::cerr << "[MainClient] Error generating AES key.\n";
        return "";
    }
    return key;
}

// Utility: Convert RSA public key (from file) to a hex string.
std::string rsaPublicKeyToHex(const std::string &pubFile) {
    FILE *fp = fopen(pubFile.c_str(), "rb");
    if (!fp) return "";
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    std::string pubData(len, '\0');
    fread(&pubData[0], 1, len, fp);
    fclose(fp);
    return MessageFormat::hexEncode(pubData);
}

// Process and decrypt a received message packet.
// Verifies the digital signature before decrypting.
void processReceivedMessage(const std::string &receivedPacket, const std::string &recipientUsername) {
    const std::string prefix = "MESSAGE|";
    std::string packet = (receivedPacket.find(prefix) == 0) ? receivedPacket.substr(prefix.length()) : receivedPacket;

    MessageFormat::SecureMessage secMsg;
    if (!MessageFormat::deserialize(packet, secMsg)) {
        std::cerr << "[MainClient] Failed to deserialize message packet.\n";
        return;
    }
    std::cout << "[Debug] Deserialized message from: " << secMsg.sender << "\n";

    // Verify digital signature.
    std::string senderPubFile = secMsg.sender + "_pub.pem";
    RSA *senderPubKey = KeyManager::loadPublicKey(senderPubFile);
    if (!senderPubKey) {
        std::cerr << "[MainClient] Failed to load sender's public key (" << senderPubFile << ").\n";
        return;
    }
    // Use the hex-encoded encrypted payload for signature verification.
    std::string encPayloadHex = secMsg.encryptedPayload;
    std::string sigDecoded = MessageFormat::hexDecode(secMsg.signature);
    std::vector<unsigned char> signature(sigDecoded.begin(), sigDecoded.end());
    if (!CryptoUtils::verifySignature(encPayloadHex, signature, senderPubKey)) {
        std::cerr << "[MainClient] Digital signature verification failed.\n";
        RSA_free(senderPubKey);
        return;
    }
    RSA_free(senderPubKey);
    std::cout << "[Debug] Digital signature verified successfully.\n";

    // Find the RSA-encrypted AES key for this recipient.
    std::string encryptedAESKeyHex;
    for (const auto &entry : secMsg.encryptedKeys) {
        if (entry.first == recipientUsername) {
            encryptedAESKeyHex = entry.second;
            break;
        }
    }
    if (encryptedAESKeyHex.empty()) {
        std::cerr << "[MainClient] No encrypted AES key found for " << recipientUsername << ".\n";
        return;
    }
    std::cout << "[Debug] Encrypted AES key hex: " << encryptedAESKeyHex << "\n";

    std::string encryptedAESKey = MessageFormat::hexDecode(encryptedAESKeyHex);
    RSA *recipientPrivKey = KeyManager::loadPrivateKey(recipientUsername + "_priv.pem");
    if (!recipientPrivKey) {
        std::cerr << "[MainClient] Failed to load RSA private key for " << recipientUsername << ".\n";
        return;
    }
    std::string aesKey;
    if (!CryptoUtils::rsaDecryptAESKey(encryptedAESKey, recipientPrivKey, aesKey)) {
        std::cerr << "[MainClient] Failed to decrypt AES key.\n";
        RSA_free(recipientPrivKey);
        ERR_print_errors_fp(stderr);
        return;
    }
    RSA_free(recipientPrivKey);
    std::cout << "[Debug] Decrypted AES key (hex): " << MessageFormat::hexEncode(aesKey) << "\n";

    std::string iv = MessageFormat::hexDecode(secMsg.iv);
    std::string encryptedPayload = MessageFormat::hexDecode(secMsg.encryptedPayload);
    std::string decryptedMessage;
    if (!CryptoUtils::aesDecrypt(encryptedPayload, aesKey, iv, decryptedMessage)) {
        std::cerr << "[MainClient] AES decryption failed.\n";
        ERR_print_errors_fp(stderr);
        return;
    }
    std::cout << "\n[Client] " << secMsg.sender << ": " << decryptedMessage << "\n> ";
}

int main() {
    std::string serverIP;
    int serverPort;
    std::cout << "Enter server IP: ";
    std::cin >> serverIP;
    std::cout << "Enter server port: ";
    std::cin >> serverPort;
    std::cin.ignore();

    std::string username;
    std::cout << "Enter your username: ";
    std::getline(std::cin, username);

    // Generate RSA keys for this user.
    std::string pubFile = username + "_pub.pem";
    std::string privFile = username + "_priv.pem";
    if (!KeyManager::generateRSAKeyPair(pubFile, privFile)) {
        std::cerr << "[MainClient] Failed to generate RSA keys.\n";
        return 1;
    }
    RSA *pubKey = KeyManager::loadPublicKey(pubFile);
    RSA *privKey = KeyManager::loadPrivateKey(privFile);
    if (!pubKey || !privKey) {
        std::cerr << "[MainClient] Failed to load RSA keys.\n";
        return 1;
    }
    std::string pubKeyHex = rsaPublicKeyToHex(pubFile);

    // Create and connect the client.
    NetworkComm::Client client(serverIP, serverPort);
    if (!client.connectToServer()) {
        std::cerr << "[MainClient] Could not connect to server.\n";
        return 1;
    }
    if (!client.registerUser(username, pubKeyHex)) {
        std::cerr << "[MainClient] Registration failed.\n";
        return 1;
    }
    std::cout << "[MainClient] Registered as " << username << ".\n";

    // Set the onMessageReceived callback to automatically decrypt and display messages.
    client.setOnMessageReceived([&](const std::string &msg) {
        processReceivedMessage(msg, username);
        std::cout << "> ";
        std::cout.flush();
    });

    client.startReceiving();

    // Main menu loop.
    while (true) {
        std::cout << "\nMenu:\n1. Send Message\n2. Exit\nChoice: ";
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        if (choice == 1) {
            std::string recipients;
            std::cout << "Enter recipients (comma separated): ";
            std::getline(std::cin, recipients);
            std::string message;
            std::cout << "Enter your message: ";
            std::getline(std::cin, message);

            // Ensure the sender's username is included so they receive a copy.
            if (recipients.find(username) == std::string::npos) {
                if (recipients.empty())
                    recipients = username;
                else
                    recipients += "," + username;
            }

            // Encrypt the message using a random AES key.
            size_t aesKeySize = 16; // AES-128
            std::string aesKey = generateRandomAESKey(aesKeySize);
            if (aesKey.empty()) continue;
            std::string encryptedPayload, iv;
            if (!CryptoUtils::aesEncrypt(message, aesKey, encryptedPayload, iv)) {
                std::cerr << "[MainClient] AES encryption failed.\n";
                continue;
            }
            // Get the hex-encoded encrypted payload for signing.
            std::string encPayloadHex = MessageFormat::hexEncode(encryptedPayload);

            // Prepare the encrypted AES keys for each recipient.
            std::vector<std::pair<std::string, std::string>> encryptedKeys;
            std::istringstream iss(recipients);
            std::string rec;
            while (std::getline(iss, rec, ',')) {
                // Trim spaces.
                rec.erase(0, rec.find_first_not_of(" \t\n\r"));
                rec.erase(rec.find_last_not_of(" \t\n\r") + 1);
                // Validate recipient name length.
                if (rec.size() < 3 || rec.size() > 20) {
                    std::cerr << "[MainClient] Invalid recipient name: " << rec << "\n";
                    continue;
                }
                std::cout << "[Debug] Loading public key for recipient: " << rec << "\n";
                RSA *recipientPubKey = KeyManager::loadPublicKey(rec + "_pub.pem");
                if (!recipientPubKey) {
                    std::cerr << "[MainClient] Failed to load public key for recipient " << rec << ".\n";
                    continue;
                }
                std::string encryptedKey;
                if (!CryptoUtils::rsaEncryptAESKey(aesKey, recipientPubKey, encryptedKey)) {
                    std::cerr << "[MainClient] Failed to encrypt AES key for recipient " << rec << ".\n";
                    RSA_free(recipientPubKey);
                    continue;
                }
                RSA_free(recipientPubKey);
                encryptedKeys.push_back({rec, MessageFormat::hexEncode(encryptedKey)});
            }

            // Sign the hex-encoded encrypted payload.
            std::vector<unsigned char> signatureVec;
            if (!CryptoUtils::signMessage(encPayloadHex, privKey, signatureVec)) {
                std::cerr << "[MainClient] Failed to sign message.\n";
            }
            std::string signature(reinterpret_cast<char*>(signatureVec.data()), signatureVec.size());

            MessageFormat::SecureMessage secMsg;
            secMsg.sender = username;
            std::istringstream rstream(recipients);
            while (std::getline(rstream, rec, ',')) {
                rec.erase(0, rec.find_first_not_of(" \t\n\r"));
                rec.erase(rec.find_last_not_of(" \t\n\r") + 1);
                secMsg.recipients.push_back(rec);
            }
            secMsg.encryptedKeys = encryptedKeys;
            secMsg.iv = MessageFormat::hexEncode(iv);
            secMsg.encryptedPayload = encPayloadHex; // already hex-encoded
            secMsg.signature = MessageFormat::hexEncode(signature);
            std::string serializedMsg = MessageFormat::serialize(secMsg);
            client.sendMessage(serializedMsg);
            std::cout << "[MainClient] Message sent.\n";
        } else if (choice == 2) {
            break;
        }
    }

    client.stopReceiving();
    RSA_free(pubKey);
    RSA_free(privKey);
    return 0;
}
