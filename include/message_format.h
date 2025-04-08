#ifndef MESSAGE_FORMAT_H
#define MESSAGE_FORMAT_H

#include <string>
#include <vector>
#include <utility>

namespace MessageFormat {

    struct SecureMessage {
        std::string sender;
        std::vector<std::string> recipients;
        // Each pair: (recipient, RSA-encrypted AES key in hex)
        std::vector<std::pair<std::string, std::string>> encryptedKeys;
        std::string iv;              // IV in hex
        std::string encryptedPayload; // Encrypted payload in hex
        std::string signature;       // Digital signature in hex
    };

    // Serializes the SecureMessage into a single string.
    std::string serialize(const SecureMessage &msg);

    // Deserializes a string into a SecureMessage.
    bool deserialize(const std::string &data, SecureMessage &msg);

    // Hex encoding/decoding utilities.
    std::string hexEncode(const std::string &data);
    std::string hexDecode(const std::string &hexData);
}

#endif // MESSAGE_FORMAT_H
