#include <iostream>
#include "network_comm.h"

int main() {
    int port;
    std::cout << "Enter port for server: ";
    std::cin >> port;
    NetworkComm::Server server(port);
    if(!server.start()) {
        std::cerr << "Server failed to start.\n";
        return 1;
    }
    return 0;
}
