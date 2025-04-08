#ifndef MAIN_CLIENT_GUI_H
#define MAIN_CLIENT_GUI_H

#include <QWidget>
#include <string>
#include <utility> // For std::pair

// Forward declarations
class QListWidget; // Changed from QTextEdit
class QLineEdit;
class QLabel;
class QListWidgetItem; // Needed for custom widgets later
namespace NetworkComm { class Client; }
namespace MessageFormat { struct SecureMessage; }
typedef struct rsa_st RSA;

class SecureMessengerGUI : public QWidget {
    Q_OBJECT

public:
    SecureMessengerGUI(QWidget* parent = nullptr,
                       const std::string &username = "",
                       const std::string &ip = "",
                       int port = 0);
    ~SecureMessengerGUI();

private slots:
    void sendMessage();
    void displayReceivedMessage(const QString& sender, const QString& messageContent); // Modified signature
    void updateStatus(const QString& status, bool isError = false);


private:
    void setupUI();
    bool setupClient();
    std::pair<bool, std::string> decryptMessage(const MessageFormat::SecureMessage &secMsg);
    void addChatItem(const QString& sender, const QString& messageContent, bool sentByMe); // Helper to add items

    // UI Elements
    QListWidget* m_chatDisplay; // Changed from QTextEdit
    QLineEdit* m_messageInput;
    QLabel* m_statusLabel;

    // Backend Data
    std::string m_username;
    std::string m_ip;
    int m_port;
    RSA* m_privKey;
    NetworkComm::Client* m_client;
    bool m_isConnected;
};

#endif // MAIN_CLIENT_GUI_H