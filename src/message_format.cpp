#include "message_format.h"
#include <sstream>
#include <iomanip>
#include <cstdlib>

namespace MessageFormat {

std::string hexEncode(const std::string &data) {
    std::ostringstream oss;
    for (unsigned char c : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return oss.str();
}

std::string hexDecode(const std::string &hexData) {
    std::string result;
    for (size_t i = 0; i < hexData.length(); i += 2) {
        std::string byteString = hexData.substr(i, 2);
        char byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

std::string serialize(const SecureMessage &msg) {
    std::ostringstream oss;
    oss << msg.sender << "|";
    for (size_t i = 0; i < msg.recipients.size(); i++) {
        oss << msg.recipients[i];
        if (i != msg.recipients.size() - 1)
            oss << ",";
    }
    oss << "|";
    for (size_t i = 0; i < msg.encryptedKeys.size(); i++) {
        oss << msg.encryptedKeys[i].first << ":" << msg.encryptedKeys[i].second;
        if (i != msg.encryptedKeys.size() - 1)
            oss << ",";
    }
    oss << "|";
    oss << msg.iv << "|";
    oss << msg.encryptedPayload << "|";
    oss << msg.signature;
    return oss.str();
}

bool deserialize(const std::string &data, SecureMessage &msg) {
    std::istringstream iss(data);
    std::string token;
    if (!std::getline(iss, msg.sender, '|'))
        return false;
    std::string recipientsStr;
    if (!std::getline(iss, recipientsStr, '|'))
        return false;
    std::istringstream recStream(recipientsStr);
    while (std::getline(recStream, token, ',')) {
        msg.recipients.push_back(token);
    }
    std::string keysStr;
    if (!std::getline(iss, keysStr, '|'))
        return false;
    std::istringstream keyStream(keysStr);
    while (std::getline(keyStream, token, ',')) {
        size_t pos = token.find(':');
        if (pos == std::string::npos)
            continue;
        std::string recipient = token.substr(0, pos);
        std::string encKey = token.substr(pos + 1);
        msg.encryptedKeys.push_back({recipient, encKey});
    }
    if (!std::getline(iss, msg.iv, '|'))
        return false;
    if (!std::getline(iss, msg.encryptedPayload, '|'))
        return false;
    std::getline(iss, msg.signature, '|');
    return true;
}

} // namespace MessageFormat
