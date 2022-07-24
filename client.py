# Version: Python 3.10.5 (Which should work for 3.7 on CSE machines)

import pickle
import sys
from socket import *

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 2000
SERVER_ADDRESS = (SERVER_HOST, SERVER_PORT)

CLIENT_HOST = '127.0.0.1'
HEADER = 1024

# ----------------------------------------------------------------
# Authentification methods.
# ----------------------------------------------------------------

def process_login():
    # Handle username.
    while True:
        # Obtain and send username.
        username = input("Username: ")

        if not username:
            print("No username supplied. Please try again")
            continue

        clientSocket.sendall(username.encode())

        # Recieve username validity.
        username_is_valid = clientSocket.recv(HEADER)
        username_is_valid = pickle.loads(username_is_valid)

        if username_is_valid:
            break

        print("Unknown username. Please try again")

    # Recieve user timeout status.
    user_blocked = clientSocket.recv(HEADER)
    user_blocked = pickle.loads(user_blocked)

    if user_blocked:
        print("User has been blocked. Please try again later")
        close_client() 

    # Handle password.
    while True:
        # Obtain and send password.
        password = input("Password: ")
        clientSocket.sendall(password.encode())

        # Receive password validity.
        password_status = clientSocket.recv(HEADER)
        password_status = pickle.loads(password_status)

        if not password_status["password_is_valid"] and password_status["blocked"]:
            print("Invalid Password. You have been blocked")
            close_client()

        if password_status["password_is_valid"]:
            break

        print("Invalid Password. Please try again")

    # Authentication was a success.
    send_UDP_socket()

    # Receive login status.
    login_success = clientSocket.recv(HEADER)
    login_success = pickle.loads(login_success)
    if not login_success:
        print("User already logged in.")
        close_client()

    print("Welcome to Toom!")
    print()

    return username

def send_UDP_socket():
    clientSocket.sendall(pickle.dumps(UDP_port_number))

# ----------------------------------------------------------------
# Start function.
# ----------------------------------------------------------------

def create_request(type, user, data):
    request = {
        "type": type,
        "user": user,
        "data": data,
    }
    return request

def create_command_request(user, command, command_args):
    command_data = {
        "command": command,
        "command_args": command_args,
    }
    return create_request("command", user, command_data)

def start():
    """Starts the client.
    """

    # First receive authentification request from the server. 
    data = clientSocket.recv(HEADER)
    response = pickle.loads(data)

    if response["request_type"] == "login":
        username = process_login()

    client_alive = True
    while client_alive:
        print("=============================================================================")
        print("Enter one of the following commands (BCM, ATU, SRB, SRM, RDM, UDP, OUT):")
        command = input(">> ")

        # If no command was supplied.
        if not command:
            print("No command supplied")
            continue

        # Send command request.
        command_type = command.split(maxsplit=1)[0]
        command_args = command.split(maxsplit=1)[1:]

        request = create_command_request(username, command_type, command_args)

        # Send request.
        clientSocket.sendall(pickle.dumps(request))

        # Get response.
        response = clientSocket.recv(HEADER)
        response = pickle.loads(response)
        print(response["requested_data"])

        if not response["keep_alive"]:
            client_alive = False

    close_client()

def close_client():
    clientSocket.close()
    clientSocketUDP.close()
    sys.exit(0)

# ----------------------------------------------------------------
# Main function.
# ----------------------------------------------------------------

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 client.py <client-udp-port>")
        sys.exit(1)

    UDP_port_number = int(sys.argv[1])

    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(SERVER_ADDRESS)

    clientSocketUDP = socket(AF_INET, SOCK_DGRAM)
    clientSocketUDP.bind((CLIENT_HOST, UDP_port_number))

    # Start client.
    start()