#!/usr/bin/env python3
"""Server for multithreaded (asynchronous) chat application."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread


def get_user_public_key(username):
    for sock in clients:
        client_data = clients[sock]
        if client_data["name"] == username:
            return client_data


def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        client.send(bytes("Greetings from the cave! Now type your name and press enter!", "utf8"))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection."""

    welcome_message = client.recv(BUFSIZ).decode("utf8")
    welcome_message = welcome_message.split(":")
    name = welcome_message[2]
    clients[client] = {
        "name": name,
        "key": welcome_message[3]
    }
    while True:
        raw_msg = client.recv(BUFSIZ)
        print(raw_msg)
        # Process System Messages
        if raw_msg.decode("utf8").startswith("SYS"):
            raw_msg = raw_msg.decode("utf8")
            print(raw_msg)
            raw_msg = raw_msg.split(":")
            command = raw_msg[1]
            value = raw_msg[2]
            # print(command, value)
            if command == "REQUEST_USER_KEY":
                user_data = get_user_public_key(username=value)
                print(user_data)
                if user_data:
                    client.send(bytes(f"{user_data['key']}", "utf8"))
                else:
                    client.send(bytes(f"No chat initiate with that user", "utf8"))

        else:
            msg = ""
            print(msg)

            if msg != bytes("{quit}", "utf8"):
                broadcast(msg, name + ": ")
            else:
                client.send(bytes("{quit}", "utf8"))
                client.close()
                del clients[client]
                broadcast(bytes("%s has left the chat." % name, "utf8"))
                break


def broadcast(msg, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""

    for sock in clients:
        sock.send(bytes(prefix, "utf8") + msg)


clients = {}
addresses = {}

HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(5)
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
