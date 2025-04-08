#include "network_comm.h"
#include <iostream>
#include <thread>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

namespace NetworkComm {

Client::Client(const std::string &serverIP, int serverPort)
    : serverIP(serverIP), serverPort(serverPort), sock(-1), connected(false), receiving(false) {}

Client::~Client() {
    stopReceiving();
    if(sock != -1) close(sock);
}

bool Client::connectToServer() {
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == -1) {
        std::cerr << "[Client] Failed to create socket.\n";
        return false;
    }
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    if(inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0) {
        std::cerr << "[Client] Invalid server IP.\n";
        return false;
    }
    if(connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "[Client] Connection to server failed.\n";
        return false;
    }
    connected = true;
    return true;
}

bool Client::registerUser(const std::string &username, const std::string &publicKeyHex) {
    if(!connected) return false;
    std::string regMsg = "REGISTER|" + username + "|" + publicKeyHex + "|";
    if(send(sock, regMsg.c_str(), regMsg.size(), 0) < 0) {
        std::cerr << "[Client] Registration failed.\n";
        return false;
    }
    return true;
}

bool Client::sendMessage(const std::string &messagePacket) {
    if(!connected) return false;
    std::string fullMsg = "MESSAGE|" + messagePacket;
    if(send(sock, fullMsg.c_str(), fullMsg.size(), 0) < 0) {
        std::cerr << "[Client] Failed to send message.\n";
        return false;
    }
    return true;
}

void Client::startReceiving() {
    receiving = true;
    receiveThread = std::thread(&Client::receiveHandler, this);
    receiveThread.detach();
}

void Client::stopReceiving() {
    receiving = false;
    if(sock != -1) close(sock);
}

void Client::setOnMessageReceived(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(recvMutex);
    onMessageReceived = callback;
}

void Client::receiveHandler() {
    char buffer[4096];
    while(receiving) {
        ssize_t len = recv(sock, buffer, sizeof(buffer)-1, 0);
        if(len <= 0) break;
        buffer[len] = '\0';
        std::lock_guard<std::mutex> lock(recvMutex);
        if(onMessageReceived)
            onMessageReceived(std::string(buffer));
        else
            std::cout << "[Client] Received: " << buffer << std::endl;
    }
}

} // namespace NetworkComm
