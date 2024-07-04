#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>
#include <fstream>
#include <openssl/aes.h>
#include <openssl/rand.h>

using namespace std;

constexpr int PORT = 8080;
constexpr size_t BUFFER_SIZE = 1024;
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

void logMessage(const string& message) {
    ofstream logFile("server_chat_logs.txt", ios::app);
    if (logFile.is_open()) {
        logFile << message << endl;
    } else {
        cerr << "Failed to open log file." << endl;
    }
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        perror("Bind failed");
        return EXIT_FAILURE;
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        return EXIT_FAILURE;
    }

    cout << "Server listening on port " << PORT << endl;

    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd < 0) {
        perror("Accept failed");
        return EXIT_FAILURE;
    }

    cout << "Client connected." << endl;
    bool authenticated = false;
    while (!authenticated) {
        char buffer[BUFFER_SIZE] = {};
        int bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received < 0) {
            perror("Error receiving data");
            continue;
        }

        buffer[bytes_received] = '\0';  // Ensure null-termination
        string credentials = decrypt(string(buffer, bytes_received));
        size_t separator = credentials.find(':');
        if (separator != string::npos) {
            string username = credentials.substr(0, separator);
            string password = credentials.substr(separator + 1);
            if (username == "user" && password == "password") {
                const char *auth_success = "Authenticated\n";
                send(client_fd, auth_success, strlen(auth_success), 0);
                authenticated = true;
                cout << "Authentication successful!" << endl;
            } else {
                const char *auth_failure = "Authentication failed\n";
                send(client_fd, auth_failure, strlen(auth_failure), 0);
            }
        }
    }

    // Handling communication after successful authentication
    char msg_buffer[BUFFER_SIZE] = {};
    while (true) {
        memset(msg_buffer, 0, BUFFER_SIZE);
        int bytes_read = recv(client_fd, msg_buffer, BUFFER_SIZE - 1, 0);
        if (bytes_read <= 0) break;

        string received_message = decrypt(string(msg_buffer, bytes_read));
        cout << "Client: " << received_message << endl;
        logMessage(received_message);  // Log the decrypted message

        string reply = "Echo: " + received_message;
        string encrypted_reply = encrypt(reply);
        send(client_fd, encrypted_reply.c_str(), encrypted_reply.size(), 0);
    }

    close(client_fd);
    close(server_fd);
    return 0;
}
