#include "main_client_gui.h"
#include "network_comm.h"
#include "key_manager.h"
#include "crypto_utils.h"
#include "message_format.h"

#include <QApplication>
#include <QListWidget> // Changed
#include <QListWidgetItem> // Added
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QInputDialog>
#include <QVBoxLayout>
#include <QMessageBox>
#include <QMetaObject>
#include <sstream>
#include <iostream>
#include <vector>
#include <utility>

#include <openssl/rand.h>
#include <openssl/err.h>

// --- Helper Functions ---

std::string generateRandomAESKey(size_t length) {
    std::string key;
    key.resize(length);
    if (!RAND_bytes(reinterpret_cast<unsigned char*>(&key[0]), length)) {
        std::cerr << "[Helper] Error generating AES key.\n";
        ERR_print_errors_fp(stderr);
        return "";
    }
    return key;
}

std::string rsaPublicKeyToHex(const std::string &pubFile) {
    FILE *fp = fopen(pubFile.c_str(), "rb");
    if (!fp) {
         std::cerr << "[Helper] Failed to open public key file: " << pubFile << std::endl;
         return "";
    }
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (len <= 0) {
        fclose(fp);
        std::cerr << "[Helper] Invalid public key file size for: " << pubFile << std::endl;
        return "";
    }
    std::string pubData(len, '\0');
    size_t bytesRead = fread(&pubData[0], 1, len, fp);
    fclose(fp);
     if (bytesRead != static_cast<size_t>(len)) {
        std::cerr << "[Helper] Failed to read entire public key file: " << pubFile << std::endl;
        return "";
    }
    return MessageFormat::hexEncode(pubData);
}

// --- SecureMessengerGUI Implementation ---

SecureMessengerGUI::SecureMessengerGUI(QWidget* parent, const std::string &username, const std::string &ip, int port)
    : QWidget(parent),
      m_chatDisplay(nullptr), m_messageInput(nullptr), m_statusLabel(nullptr),
      m_username(username), m_ip(ip), m_port(port),
      m_privKey(nullptr), m_client(nullptr), m_isConnected(false)
{
    setupUI();
    if (!setupClient()) {
         QMessageBox::critical(this, "Initialization Error", "Failed to set up client. Please check keys and connection.");
    }
}

SecureMessengerGUI::~SecureMessengerGUI() {
    if (m_client) {
        m_client->stopReceiving();
        delete m_client;
        m_client = nullptr;
    }
    if (m_privKey) {
        RSA_free(m_privKey);
        m_privKey = nullptr;
    }
}


void SecureMessengerGUI::setupUI() {
    QVBoxLayout* layout = new QVBoxLayout(this);
    m_chatDisplay = new QListWidget(this); // Changed
    m_chatDisplay->setWordWrap(true); // Optional: improve wrapping in list items
    // Prevent user selection/editing of items
    m_chatDisplay->setSelectionMode(QAbstractItemView::NoSelection);
    m_chatDisplay->setFocusPolicy(Qt::NoFocus);


    m_messageInput = new QLineEdit(this);
    m_messageInput->setPlaceholderText("Enter message here...");
    QPushButton* sendBtn = new QPushButton("Send", this);
    m_statusLabel = new QLabel("Disconnected", this);

    layout->addWidget(m_chatDisplay);
    layout->addWidget(m_messageInput);
    layout->addWidget(sendBtn);
    layout->addWidget(m_statusLabel);

    connect(sendBtn, &QPushButton::clicked, this, &SecureMessengerGUI::sendMessage);
    connect(m_messageInput, &QLineEdit::returnPressed, sendBtn, &QPushButton::click);
}

bool SecureMessengerGUI::setupClient() {
    updateStatus("Initializing...", false);
    m_isConnected = false;

    // Key Management
    std::string pubFile = m_username + "_pub.pem";
    std::string privFile = m_username + "_priv.pem";
    m_privKey = KeyManager::loadPrivateKey(privFile);
    if (!m_privKey) {
        std::cout << "[GUI Setup] Generating new key pair for " << m_username << std::endl;
        if (!KeyManager::generateRSAKeyPair(pubFile, privFile)) {
            updateStatus("Error: Failed to generate RSA keys.", true);
            return false;
        }
        m_privKey = KeyManager::loadPrivateKey(privFile);
        if (!m_privKey) {
            updateStatus("Error: Failed to load generated RSA private key.", true);
             return false;
        }
    }
    std::string pubKeyHex = rsaPublicKeyToHex(pubFile);
    if (pubKeyHex.empty()) {
        updateStatus("Error: Failed to read public key for registration.", true);
        return false;
    }

    // Network Initialization
    m_client = new NetworkComm::Client(m_ip, m_port);
    bool connectionSuccess = m_client->connectToServer();

    if (connectionSuccess) {
        bool registrationSuccess = m_client->registerUser(m_username, pubKeyHex);
        if (registrationSuccess) {
            m_isConnected = true;

            // Setup Message Reception
            m_client->setOnMessageReceived([this](const std::string &msg) {
                const std::string prefix = "MESSAGE|";
                std::string packet = (msg.find(prefix) == 0) ? msg.substr(prefix.length()) : msg;
                MessageFormat::SecureMessage secMsg;

                if(MessageFormat::deserialize(packet, secMsg)) {
                     // *** FIX: Ignore own messages received back ***
                     if (secMsg.sender == this->m_username) {
                         return;
                     }
                     // *** END FIX ***

                    auto [success, result] = decryptMessage(secMsg);
                    if (success) {
                        // Pass sender and message separately for UI formatting
                        QMetaObject::invokeMethod(this, "displayReceivedMessage", Qt::QueuedConnection,
                                                  Q_ARG(QString, QString::fromStdString(secMsg.sender)),
                                                  Q_ARG(QString, QString::fromStdString(result)));
                    } else {
                        QString errorText = "[Error decrypting from " + QString::fromStdString(secMsg.sender) + ": " + QString::fromStdString(result) + "]";
                         QMetaObject::invokeMethod(this, "displayReceivedMessage", Qt::QueuedConnection,
                                                  Q_ARG(QString, QString("System")), // Or empty sender
                                                  Q_ARG(QString, errorText));
                    }
                } else {
                     std::cerr << "[GUI Receive] Failed to deserialize received message.\n";
                     QMetaObject::invokeMethod(this, "displayReceivedMessage", Qt::QueuedConnection,
                                               Q_ARG(QString, QString("System")),
                                               Q_ARG(QString, QString("[Error: Invalid message format received]")));
                }
            });

            m_client->startReceiving();
            updateStatus("Connected", false);
            return true;

        } else {
            updateStatus("Error: Registration failed.", true);
            return false;
        }
    } else {
        updateStatus("Error: Connection failed.", true);
        return false;
    }
}

void SecureMessengerGUI::updateStatus(const QString& status, bool isError) {
     m_statusLabel->setText(status);
     m_statusLabel->setStyleSheet(isError ? "QLabel { color : red; }" : "");
}

void SecureMessengerGUI::displayReceivedMessage(const QString& sender, const QString& messageContent) {
    // Slot runs in the main GUI thread
    addChatItem(sender, messageContent, false); // false means not sent by me
}

// Helper function to add items to the list widget
void SecureMessengerGUI::addChatItem(const QString& sender, const QString& messageContent, bool sentByMe) {
    // Create a simple QLabel placeholder for the message bubble
    QLabel* bubbleLabel = new QLabel(this);
    bubbleLabel->setWordWrap(true);

    QString displayText;
    Qt::Alignment alignment;

    if (sentByMe) {
        displayText = "You: " + messageContent;
        alignment = Qt::AlignRight; // Align text right for sent messages
        // Optional: Style differently
        bubbleLabel->setStyleSheet("QLabel { background-color: #DCF8C6; padding: 5px; border-radius: 5px; }");
    } else {
        displayText = sender + ": " + messageContent;
        alignment = Qt::AlignLeft; // Align text left for received messages
        // Optional: Style differently
        bubbleLabel->setStyleSheet("QLabel { background-color: white; padding: 5px; border-radius: 5px; }");
    }

    bubbleLabel->setText(displayText);
    bubbleLabel->setAlignment(alignment);


    // Create list item and set its size hint
    QListWidgetItem* item = new QListWidgetItem(m_chatDisplay);
    item->setSizeHint(bubbleLabel->sizeHint()); // Adjust item size to bubble size

    // Add item and set the custom widget
    m_chatDisplay->addItem(item);
    m_chatDisplay->setItemWidget(item, bubbleLabel);

    // Ensure the new item is visible
    m_chatDisplay->scrollToBottom();
}


void SecureMessengerGUI::sendMessage() {
    if (!m_isConnected) {
        QMessageBox::warning(this, "Not Connected", "You are not connected to the server.");
        return;
    }
    if (!m_privKey) {
         QMessageBox::critical(this, "Error", "Private key is not loaded. Cannot send message.");
         return;
    }

    QString recipientsQS = QInputDialog::getText(this, "Recipients", "Enter comma-separated recipients:", QLineEdit::Normal);
    if (recipientsQS.isEmpty()) return;

    QString message = m_messageInput->text();
    if(message.isEmpty()) return;

    std::string recipients = recipientsQS.toStdString();
    if (recipients.find(m_username) == std::string::npos) {
        if (recipients.empty()) recipients = m_username;
        else recipients += "," + m_username;
    }

    // Encryption
    size_t aesKeySize = 16;
    std::string aesKey = generateRandomAESKey(aesKeySize);
    if (aesKey.empty()) {
         QMessageBox::critical(this, "Error", "Failed to generate AES key.");
         return;
    }
    std::string encryptedPayload;
    std::string iv;
    if(!CryptoUtils::aesEncrypt(message.toStdString(), aesKey, encryptedPayload, iv)) {
         ERR_print_errors_fp(stderr);
         QMessageBox::critical(this, "Error", "AES encryption failed.");
         return;
    }
    std::string encPayloadHex = MessageFormat::hexEncode(encryptedPayload);
    std::string ivHex = MessageFormat::hexEncode(iv);

    // Encrypt AES Key for Recipients
    std::vector<std::pair<std::string, std::string>> encryptedKeys;
    std::istringstream iss(recipients);
    std::string rec;
    bool keyEncryptionFailed = false;
    while(std::getline(iss, rec, ',')) {
        rec.erase(0, rec.find_first_not_of(" \t\n\r"));
        rec.erase(rec.find_last_not_of(" \t\n\r") + 1);
        if (rec.empty()) continue;
        RSA *recipientPubKey = KeyManager::loadPublicKey(rec + "_pub.pem");
        if(!recipientPubKey) {
            QMessageBox::warning(this, "Key Error", QString("Could not load public key for '%1'. Skipping recipient.").arg(QString::fromStdString(rec)));
            keyEncryptionFailed = true;
            continue;
        }
        std::string encryptedKeyRaw;
        if(CryptoUtils::rsaEncryptAESKey(aesKey, recipientPubKey, encryptedKeyRaw)) {
            encryptedKeys.push_back({rec, MessageFormat::hexEncode(encryptedKeyRaw)});
        } else {
             ERR_print_errors_fp(stderr);
              QMessageBox::warning(this, "Encryption Error", QString("Could not encrypt session key for '%1'. Skipping recipient.").arg(QString::fromStdString(rec)));
              keyEncryptionFailed = true;
        }
        RSA_free(recipientPubKey);
    }
     if(encryptedKeys.empty() && keyEncryptionFailed) {
         QMessageBox::critical(this, "Error", "Failed to encrypt session key for any valid recipient.");
         return;
     }

    // Signing
    std::vector<unsigned char> signatureVec;
    if (!CryptoUtils::signMessage(encPayloadHex, m_privKey, signatureVec)) {
        ERR_print_errors_fp(stderr);
        QMessageBox::critical(this, "Error", "Failed to sign the message.");
        return;
    }
    std::string signatureRaw(signatureVec.begin(), signatureVec.end());
    std::string signatureHex = MessageFormat::hexEncode(signatureRaw);

    // Assemble and Send
    MessageFormat::SecureMessage msg;
    msg.sender = m_username;
    std::istringstream rstream(recipients);
     while (std::getline(rstream, rec, ',')) {
         rec.erase(0, rec.find_first_not_of(" \t\n\r"));
         rec.erase(rec.find_last_not_of(" \t\n\r") + 1);
         if(!rec.empty()) msg.recipients.push_back(rec);
     }
    msg.encryptedKeys = encryptedKeys;
    msg.iv = ivHex;
    msg.encryptedPayload = encPayloadHex;
    msg.signature = signatureHex;

    std::string serializedMsg = MessageFormat::serialize(msg);

    if (m_client && m_client->sendMessage(serializedMsg)) {
        // Display sent message locally using the helper
        addChatItem("You", message, true); // true means sent by me
        m_messageInput->clear();
    } else {
          QMessageBox::critical(this, "Network Error", "Failed to send the message.");
    }
}


std::pair<bool, std::string> SecureMessengerGUI::decryptMessage(const MessageFormat::SecureMessage &secMsg) {
    if (!m_privKey) return {false, "Internal Error: Private key missing"};

    // Verify digital signature
    std::string senderPubFile = secMsg.sender + "_pub.pem";
    RSA *senderPubKey = KeyManager::loadPublicKey(senderPubFile);
    if (!senderPubKey) return {false, "Cannot load sender key"};

    std::string encPayloadHex = secMsg.encryptedPayload;
    std::string sigDecoded = MessageFormat::hexDecode(secMsg.signature);
    if (sigDecoded.empty() && !secMsg.signature.empty()) {
        RSA_free(senderPubKey);
        return {false, "Invalid signature format"};
    }
    std::vector<unsigned char> signature(sigDecoded.begin(), sigDecoded.end());
    if (!CryptoUtils::verifySignature(encPayloadHex, signature, senderPubKey)) {
        ERR_print_errors_fp(stderr);
        RSA_free(senderPubKey);
        return {false, "Signature verification failed"};
    }
    RSA_free(senderPubKey);

    // Find and Decrypt AES Key
    std::string encryptedAESKeyHex;
    bool foundKey = false;
    for(const auto& [recipient, key] : secMsg.encryptedKeys) {
        if(recipient == m_username) {
            encryptedAESKeyHex = key;
            foundKey = true;
            break;
        }
    }
    if (!foundKey) return {false, "Message not intended for you"};

    std::string encryptedKeyRaw = MessageFormat::hexDecode(encryptedAESKeyHex);
    if (encryptedKeyRaw.empty() && !encryptedAESKeyHex.empty()) {
        return {false, "Invalid key format"};
    }
    std::string aesKey;
    if(!CryptoUtils::rsaDecryptAESKey(encryptedKeyRaw, m_privKey, aesKey)) {
        ERR_print_errors_fp(stderr);
        return {false, "Cannot decrypt session key"};
    }

    // Decrypt Payload
    std::string payloadRaw = MessageFormat::hexDecode(secMsg.encryptedPayload);
    if (payloadRaw.empty() && !secMsg.encryptedPayload.empty()) {
        return {false, "Invalid payload format"};
    }
    std::string ivRaw = MessageFormat::hexDecode(secMsg.iv);
    if (ivRaw.empty() && !secMsg.iv.empty()) {
        return {false, "Invalid IV format"};
    }
    std::string decryptedPayload;
    if(!CryptoUtils::aesDecrypt(payloadRaw, aesKey, ivRaw, decryptedPayload)) {
        ERR_print_errors_fp(stderr);
        return {false, "Payload decryption failed"};
    }

    return {true, decryptedPayload};
}


// --- Main Application Entry Point ---
int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    int numUsers = QInputDialog::getInt(nullptr, "Number of Users", "Enter number of users (min 2):", 1, 1);
    if (numUsers <= 0) {
        QMessageBox::critical(nullptr, "Error", "Number of users must be at least 1.");
        return 1;
    }

    QString serverIpQS = QInputDialog::getText(nullptr, "Server IP", "Enter server IP:", QLineEdit::Normal, QStringLiteral("127.0.0.1"));
     if (serverIpQS.isEmpty()) return 1;
    std::string ip = serverIpQS.toStdString();

    bool okPort;
    int port = QInputDialog::getInt(nullptr, "Server Port", "Enter server port:", 8080, 1024, 65535, 1, &okPort);
     if (!okPort) return 1;

    std::vector<SecureMessengerGUI*> windows; // Keep track if needed for later cleanup
     windows.reserve(numUsers);

    for (int i = 0; i < numUsers; ++i) {
         QString usernameQS = QInputDialog::getText(nullptr, "Username", QString("Enter username for user %1:").arg(i + 1));
          if (usernameQS.isEmpty()) continue;
         std::string username = usernameQS.toStdString();

        SecureMessengerGUI* window = new SecureMessengerGUI(nullptr, username, ip, port);
        window->setWindowTitle(QString("Secure Messenger - %1").arg(usernameQS));
        window->resize(450, 600); // Adjusted default size
        window->show();
        windows.push_back(window);
    }

     if (windows.empty()) {
         QMessageBox::information(nullptr, "No Windows", "No chat windows were created.");
         return 0;
     }

    int ret = app.exec();

    // Optional: Explicitly delete windows if needed, although Qt might handle it
    // for(auto w : windows) { delete w; }
    // windows.clear();

    return ret;
}