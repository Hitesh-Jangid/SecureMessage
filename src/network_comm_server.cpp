#include "network_comm.h"
#include <iostream>
#include <vector>
#include <thread>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

namespace NetworkComm {

Server::Server(int port) : port(port), serverSocket(-1), running(false) {}

Server::~Server() {
    stop();
}

bool Server::start() {
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSocket == -1) {
        std::cerr << "[Server] Failed to create socket.\n";
        return false;
    }
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if(bind(serverSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[Server] Bind failed.\n";
        return false;
    }
    if(listen(serverSocket, 5) < 0) {
        std::cerr << "[Server] Listen failed.\n";
        return false;
    }
    running = true;
    std::cout << "[Server] Listening on port " << port << std::endl;
    while(running) {
        int clientSock = accept(serverSocket, nullptr, nullptr);
        if(clientSock < 0) continue;
        std::thread(&Server::clientHandler, this, clientSock).detach();
    }
    return true;
}

void Server::stop() {
    running = false;
    if(serverSocket != -1) close(serverSocket);
}

void Server::clientHandler(int clientSocket) {
    char buffer[4096];
    ssize_t len = recv(clientSocket, buffer, sizeof(buffer)-1, 0);
    if(len <= 0) {
        close(clientSocket);
        return;
    }
    buffer[len] = '\0';
    std::string initMsg(buffer);
    // Expect format: "REGISTER|username|publicKeyHex|"
    std::string username;
    size_t pos = initMsg.find('|');
    if(pos != std::string::npos) {
        username = initMsg.substr(pos+1, initMsg.find('|', pos+1) - pos - 1);
    }
    {
        std::lock_guard<std::mutex> lock(clientMutex);
        clients.push_back({clientSocket, username, ""});
    }
    std::cout << "[Server] User registered: " << username << std::endl;
    while((len = recv(clientSocket, buffer, sizeof(buffer)-1, 0)) > 0) {
        buffer[len] = '\0';
        std::string msg(buffer);
        broadcastMessage(msg);
    }
    close(clientSocket);
    std::cout << "[Server] User disconnected: " << username << std::endl;
}

void Server::broadcastMessage(const std::string &messagePacket) {
    std::lock_guard<std::mutex> lock(clientMutex);
    for(auto &client : clients) {
        send(client.socket, messagePacket.c_str(), messagePacket.size(), 0);
    }
}

} // namespace NetworkComm
