#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace std;

constexpr int PORT = 8080;
unsigned char aes_key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe};

string encrypt(const string& data) {
    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 128, &enc_key);
    string encrypted;
    size_t blocks = data.size() / AES_BLOCK_SIZE + (data.size() % AES_BLOCK_SIZE != 0);
    for (size_t i = 0; i < blocks; ++i) {
        unsigned char out[AES_BLOCK_SIZE];
        string block = data.substr(i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        block.append(AES_BLOCK_SIZE - block.size(), ' ');  // padding with spaces
        AES_encrypt(reinterpret_cast<const unsigned char*>(block.c_str()), out, &enc_key);
        encrypted.append(reinterpret_cast<char*>(out), AES_BLOCK_SIZE);
    }
    return encrypted;
}

string decrypt(const string& encrypted) {
    AES_KEY dec_key;
    AES_set_decrypt_key(aes_key, 128, &dec_key);
    string decrypted;
    for (size_t i = 0; i < encrypted.size(); i += AES_BLOCK_SIZE) {
        unsigned char out[AES_BLOCK_SIZE];
        AES_decrypt(reinterpret_cast<const unsigned char*>(encrypted.c_str() + i), out, &dec_key);
        decrypted.append(reinterpret_cast<char*>(out), AES_BLOCK_SIZE);
    }
    return decrypted.substr(0, decrypted.find_last_not_of(' ') + 1);  // trim padding
}

void logMessage(const string& prefix, const string& message) {
    ofstream logFile("client_chat_logs.txt", ios::app);
    if (logFile.is_open()) {
        logFile << prefix << message << endl;
    } else {
        cerr << "Failed to open log file." << endl;
    }
}

int main() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sockfd, reinterpret_cast<sockaddr*>(&serv_addr), sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return EXIT_FAILURE;
    }

    cout << "Connected to server. Please authenticate." << endl;

    // Authentication
    bool authenticated = false;
    while (!authenticated) {
        cout << "Username: ";
        string username;
        getline(cin, username);

        cout << "Password: ";
        string password;
        getline(cin, password);

        string credentials = username + ":" + password;
        string encrypted_credentials = encrypt(credentials);
        send(sockfd, encrypted_credentials.c_str(), encrypted_credentials.size(), 0);

        char auth_response[1024] = {};
        int bytes_recv = recv(sockfd, auth_response, sizeof(auth_response) - 1, 0);
        auth_response[bytes_recv] = '\0'; // Ensure null-terminated

        if (strcmp(auth_response, "Authenticated\n") == 0) {
            cout << "Authentication successful!" << endl;
            authenticated = true;
        } else {
            cout << "Authentication failed. Please try again.\n";
        }
    }

    // Communication with server
    if (authenticated) {
        string message;
        while (true) {
            cout << "Enter message (type 'exit' to quit): ";
            getline(cin, message);
            if (message == "exit") break;

            string encrypted_message = encrypt(message);
            send(sockfd, encrypted_message.c_str(), encrypted_message.size(), 0);
            logMessage("Sent: ", message);  // Log the sent message

            char buffer[1024] = {};
            int bytes_read = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_read <= 0) break;

            string decrypted_message = decrypt(string(buffer, bytes_read));
            cout << "Server response: " << decrypted_message << endl;
            logMessage("Received: ", decrypted_message);  // Log the received message
        }
    }

    close(sockfd);
    cout << "Disconnected from server." << endl;
    return 0;
}
