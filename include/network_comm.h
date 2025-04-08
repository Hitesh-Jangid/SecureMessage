#ifndef NETWORK_COMM_H
#define NETWORK_COMM_H

#include <string>
#include <functional>
#include <thread>
#include <mutex>
#include <vector>

namespace NetworkComm {

    class Client {
    public:
        Client(const std::string &serverIP, int serverPort);
        ~Client();
        bool connectToServer();
        bool registerUser(const std::string &username, const std::string &publicKeyHex);
        bool sendMessage(const std::string &messagePacket);
        void startReceiving();
        void stopReceiving();
        void setOnMessageReceived(std::function<void(const std::string&)> callback);
    private:
        std::string serverIP;
        int serverPort;
        int sock;
        bool connected;
        bool receiving;
        std::thread receiveThread;
        std::mutex recvMutex;
        std::function<void(const std::string&)> onMessageReceived;
        void receiveHandler();
    };

    class Server {
    public:
        Server(int port);
        ~Server();
        bool start();
        void stop();
    private:
        int port;
        int serverSocket;
        bool running;
        std::mutex clientMutex;
        struct ClientInfo {
            int socket;
            std::string username;
            std::string publicKeyHex;
        };
        std::vector<ClientInfo> clients;
        void clientHandler(int clientSocket);
        void broadcastMessage(const std::string &messagePacket);
    };
}

#endif // NETWORK_COMM_H
