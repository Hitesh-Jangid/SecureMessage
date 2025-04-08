#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QInputDialog>
#include <sstream>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "network_comm.h"
#include "key_manager.h"
#include "crypto_utils.h"
#include "message_format.h"

class SecureMessengerGUI : public QWidget {
    Q_OBJECT
public:
    SecureMessengerGUI(QWidget* parent = nullptr) : QWidget(parent) {
        setupUI();
        setupClient();
    }

private slots:
    void sendMessage() {
        QString recipients = QInputDialog::getText(this, "Recipients", 
            "Enter comma-separated recipients:", QLineEdit::Normal, QString::fromStdString(m_username));
        QString message = m_messageInput->text();
        
        if(message.isEmpty()) return;

        // Replicate CLI message sending logic
        std::string aesKey = generateRandomAESKey(16);
        std::string encryptedPayload, iv;
        if(CryptoUtils::aesEncrypt(message.toStdString(), aesKey, encryptedPayload, iv)) {
            std::vector<std::pair<std::string, std::string>> encryptedKeys;
            std::istringstream iss(recipients.toStdString());
            std::string rec;
            
            while(std::getline(iss, rec, ',')) {
                rec.erase(0, rec.find_first_not_of(" \t\n\r"));
                rec.erase(rec.find_last_not_of(" \t\n\r") + 1);
                
                RSA *pubKey = KeyManager::loadPublicKey(rec + "_pub.pem");
                if(pubKey) {
                    std::string encryptedKey;
                    if(CryptoUtils::rsaEncryptAESKey(aesKey, pubKey, encryptedKey)) {
                        encryptedKeys.push_back({rec, MessageFormat::hexEncode(encryptedKey)});
                    }
                    RSA_free(pubKey);
                }
            }

            // Create and send message
            MessageFormat::SecureMessage msg;
            msg.sender = m_username;
            msg.encryptedPayload = MessageFormat::hexEncode(encryptedPayload);
            msg.iv = MessageFormat::hexEncode(iv);
            msg.encryptedKeys = encryptedKeys;
            
            // Sign the message
            std::vector<unsigned char> signature;
            CryptoUtils::signMessage(msg.encryptedPayload, m_privKey, signature);
            msg.signature = MessageFormat::hexEncode(std::string(signature.begin(), signature.end()));
            
            m_client->sendMessage(MessageFormat::serialize(msg));
            m_chatDisplay->append("You: " + message);
            m_messageInput->clear();
        }
    }

private:
    void setupUI() {
        QVBoxLayout* layout = new QVBoxLayout(this);
        
        m_chatDisplay = new QTextEdit(this);
        m_chatDisplay->setReadOnly(true);
        
        m_messageInput = new QLineEdit(this);
        QPushButton* sendBtn = new QPushButton("Send", this);
        m_statusLabel = new QLabel("Disconnected", this);
        
        layout->addWidget(m_chatDisplay);
        layout->addWidget(m_messageInput);
        layout->addWidget(sendBtn);
        layout->addWidget(m_statusLabel);

        connect(sendBtn, &QPushButton::clicked, this, &SecureMessengerGUI::sendMessage);
    }

    void setupClient() {
        // Get credentials through dialogs
        QString username = QInputDialog::getText(this, "Username", "Enter username:");
        QString ip = QInputDialog::getText(this, "Server IP", "Enter server IP:", QLineEdit::Normal, "127.0.0.1");
        int port = QInputDialog::getInt(this, "Port", "Enter port:", 8080);

        m_username = username.toStdString();
        
        // Initialize client
        KeyManager::generateRSAKeyPair(m_username + "_pub.pem", m_username + "_priv.pem");
        m_privKey = KeyManager::loadPrivateKey(m_username + "_priv.pem");
        
        m_client = new NetworkComm::Client(ip.toStdString(), port);
        if(m_client->connectToServer() && m_client->registerUser  (m_username, rsaPublicKeyToHex(m_username + "_pub.pem"))) {
            m_client->setOnMessageReceived([this](const std::string &msg) {
                MessageFormat::SecureMessage secMsg;
                if(MessageFormat::deserialize(msg, secMsg)) {
                    std::string decrypted = decryptMessage(secMsg);
                    QMetaObject::invokeMethod(this, [this, decrypted, sender = QString::fromStdString(secMsg.sender)]() {
                        m_chatDisplay->append(sender + ": " + QString::fromStdString(decrypted));
                    });
                }
            });
            m_client->startReceiving();
            m_statusLabel->setText("Connected");
        }
    }

    std::string decryptMessage(const MessageFormat::SecureMessage &secMsg) {
        // Find our encrypted key
        for(const auto& [recipient, key] : secMsg.encryptedKeys) {
            if(recipient == m_username) {
                std::string encryptedKey = MessageFormat::hexDecode(key);
                std::string aesKey;
                if(CryptoUtils::rsaDecryptAESKey(encryptedKey, m_privKey, aesKey)) {
                    std::string payload = MessageFormat::hexDecode(secMsg.encryptedPayload);
                    std::string iv = MessageFormat::hexDecode(secMsg.iv);
                    std::string decrypted;
                    if(CryptoUtils::aesDecrypt(payload, aesKey, iv, decrypted)) {
                        return decrypted;
                    }
                }
            }
        }
        return "[Decryption failed]";
    }

    QTextEdit* m_chatDisplay;
    QLineEdit* m_messageInput;
    QLabel* m_statusLabel;
    NetworkComm::Client* m_client;
    std::string m_username;
    RSA* m_privKey;
};

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    SecureMessengerGUI gui;
    gui.show();
    return app.exec();
}