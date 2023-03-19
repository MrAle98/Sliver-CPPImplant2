#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "listeners.h"

namespace pivots {
	TCPListener::TCPListener(const std::string& _bind_address) : bind_address(_bind_address) {
        WSADATA wsaData;
        int iResult;

        this->listen_socket = INVALID_SOCKET;

        struct addrinfo* result = NULL;
        struct addrinfo hints;

        int iSendResult;

        // Initialize Winsock
        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != 0) {
            printf("WSAStartup failed with error: %d\n", iResult);
            return;
        }

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_PASSIVE;
        auto hostname = bind_address.substr(0, bind_address.find(":"));
        auto port = bind_address.substr(bind_address.find(":")+1,bind_address.size()-1);
        // Resolve the server address and port
        iResult = getaddrinfo(NULL, port.c_str(), &hints, &result);
        if (iResult != 0) {
            printf("getaddrinfo failed with error: %d\n", iResult);
            return;
        }

        // Create a SOCKET for the server to listen for client connections.
        this->listen_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (listen_socket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            freeaddrinfo(result);
            this->listen_socket = INVALID_SOCKET;
            return;
        }

        // Setup the TCP listening socket
        iResult = ::bind(this->listen_socket, result->ai_addr, (int)result->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            printf("bind failed with error: %d\n", WSAGetLastError());
            freeaddrinfo(result);
            closesocket(listen_socket);
            this->listen_socket = INVALID_SOCKET;
            return;
        }
        freeaddrinfo(result);

        iResult = listen(this->listen_socket, SOMAXCONN);
        if (iResult == SOCKET_ERROR) {
            printf("listen failed with error: %d\n", WSAGetLastError());
            closesocket(this->listen_socket);
            this->listen_socket = INVALID_SOCKET;
            return;
        }
	}
	shared_ptr<PivotConn> TCPListener::Accept() {
        auto client_socket = accept(this->listen_socket, NULL, NULL);
        if (client_socket == INVALID_SOCKET) {
            printf("accept failed with error: %d\n", WSAGetLastError());
            return nullptr;
        }
        shared_ptr<PivotConn> conn = make_shared<TCPConn>(client_socket);
		return conn;
	}
    bool TCPListener::Stop() {
        if (!closesocket(this->listen_socket)) {
            return true;
        }
        return false;
    }
    void TCPListener::Clean() {
        return;
    }
}