# Version: Python 3.10.5 (Which should work for 3.7 on CSE machines)

from datetime import datetime
import inspect
from pprint import pprint
import re
import sys
from socket import *
import textwrap
from threading import Thread
import pickle
from tkinter import N
from turtle import down
from server_data import ServerData

import validate

HOST = '127.0.0.1'
PORT = 2000
ADDRESS = (HOST, PORT)
HEADER = 1024 # Size of each TCP segment.

class ClientThread(Thread):
    """A new Thread object is created for each new client. 
    """

    # Class Constructor.
    def __init__(self, clientAddress, clientSocket, server_data):
        Thread.__init__(self) # A new thread is created when this class is instantiated.
        self.clientAddress = clientAddress
        self.clientSocket = clientSocket
        self.clientAlive = False

        # Server data.
        self.server_data = server_data
        
        print("===== New connection created for: ", clientAddress)
        self.clientAlive = True

    # ----------------------------------------------------------------
    # Driver function.
    # ----------------------------------------------------------------

    def run(self):
        """Driver code for the 
        """
        # This method is implicitly run after calling clientThread.start().
        if not self.authenticate_client():
            return
        
        pprint(self.server_data.get_active_users())
        
        # Handle Commands.
        while self.clientAlive:
            request = self.clientSocket.recv(HEADER)

            # If the message from client is empty, the client would have disconnected.
            if not request:
                self.clientAlive = False
                break

            request = pickle.loads(request)

            # Check that request from client is a command request.
            if not request["type"] == "command":
                self.clientAlive = False
                break

            user = request["user"]
            data = request["data"]
            command_args = data["command_args"]

            # Commands.
            if data["command"] == "OUT":
                # self.handle_command_OUT(request)
                if self.handle_command_OUT(user, command_args):
                    self.clientAlive = False
            elif data["command"] == "BCM":
                self.handle_command_BCM(user, command_args)
            elif data["command"] == "ATU":
                self.handle_command_ATU(user, command_args)
            else:
                print("Unkown command")

    # ----------------------------------------------------------------
    # ATU command methods.
    # ----------------------------------------------------------------

    def handle_command_ATU(self, user, command_args):
        status = True
        error_msg = ""
        if not validate.validate_no_command_args(command_args):
            error_msg = "[ERROR] ATU should have no arguments"
            status = False

        # Send error if detected.
        if not status:
            self.send_response(user, status, error_msg, True)
            return

        # Grab other active users.
        download_active_users = []
        for active_user in self.server_data.get_active_users():
            if active_user["username"] != user:
                download_active_users.append(active_user)

        # If no other active users.
        if len(download_active_users) == 0:
            data_text = self.create_response_data_format("ATU", "No other active users")
            self.send_response(user, status, data_text, True)
            return

        # Send response.
        lines = ""
        for active_user in download_active_users:
            lines += f"""> {active_user['username']}, active since {active_user['login_timestamp']}
                IP Address: {active_user['IP_address']}
                UDP Socket Port: {active_user['UDP_socket_port']}
            """
        
        data_text = """
        Active users:
            {active_users}
        """.format(active_users = lines)
        requested_data = self.create_response_data_format("ATU", data_text)
        self.send_response(user, status, requested_data, True)
    
    # ----------------------------------------------------------------
    # BCM command methods.
    # ----------------------------------------------------------------

    def handle_command_BCM(self, user, command_args):
        status = True
        error_msg = ""
        if validate.validate_no_command_args(command_args):
            error_msg = "[ERROR] No message supplied"
            status = False

        if not status:
            self.send_response(user, status, error_msg, True)
            return
        
        # Generate message id.
        message_id = 1
        if len(self.server_data.get_broadcasted_messages()) != 0:
            message_list = self.server_data.get_broadcasted_messages()
            message_id = message_list[-1]["message_id"] + 1

        # Create broadcast message.
        current_time = datetime.now()
        broadcast_msg = {
            "username": user,
            "message_id": message_id,
            "timestamp": current_time,
            "message": command_args[0],
        }
        self.server_data.create_broadcasted_message(broadcast_msg)

        # Send response.
        timestamp = self.convert_datetime_to_timestamp(current_time)
        data_text = f"""
        Broadcast message: {command_args[0]}
        By: {user}
        Timestamp: {timestamp}
        """
        requested_data = self.create_response_data_format("BCM", data_text)
        self.send_response(user, status, requested_data, True)

        # Create message log.
        self.create_message_log(broadcast_msg)

        pprint(self.server_data.get_broadcasted_messages())

    # ----------------------------------------------------------------
    # OUT command methods.
    # ----------------------------------------------------------------

    def handle_command_OUT(self, user, command_args):
        status = True
        error_msg = ""
        if not validate.validate_no_command_args(command_args):
            error_msg = "[ERROR] OUT should have no arguments"
            status = False

        # Send error if detected.
        if not status:
            self.send_response(user, status, error_msg, not status)
            return status

        # Delete active user and active user log.
        self.server_data.delete_active_user(user)
        self.delete_user_log(user)

        # Send response.
        data_text = f"{user} has successfully logged out"
        requested_data = self.create_response_data_format("OUT", data_text)
        self.send_response(user, status, requested_data, not status)

        # Print to server output.
        print(f"{user} has logged out")

        pprint(self.server_data.get_active_users())

        return status

    # ----------------------------------------------------------------
    # Response methods.
    # ----------------------------------------------------------------

    def send_response(self, user, status, requested_data, keep_alive):
        response = {
            "user": user,
            "status": status,
            "requested_data": requested_data,
            "keep_alive": keep_alive,
        }
        self.clientSocket.sendall(pickle.dumps(response))

    def create_response_data_format(self, command, text):
        data = textwrap.dedent(f"""
        -- [{command}]: Response ---------------------------------------
        {text}
        ----------------------------------------------------------
        """)
        return data

    # ----------------------------------------------------------------
    # Authentification methods.
    # ----------------------------------------------------------------

    def authenticate_client(self):
        # Send login request.
        input_login_attempts = int(sys.argv[1])
        msg = {
            "request_type": "login",
        }
        self.clientSocket.sendall(pickle.dumps(msg))

        # Authenticate client username.
        while True:
            username = self.clientSocket.recv(HEADER).decode()
            username_is_valid = self.server_data.valid_username(username)

            self.clientSocket.sendall(pickle.dumps(username_is_valid))

            if username_is_valid:
                break

        # Check if user has been blocked.
        user_blocked = self.server_data.user_is_blocked(username)
        print(user_blocked)
        self.clientSocket.sendall(pickle.dumps(user_blocked))
        if user_blocked:
            return False

        # Authenticate password for current client.
        blocked = False
        attempts = 1
        while True:
            password = self.clientSocket.recv(HEADER).decode()
            password_is_valid = self.server_data.valid_user(username, password)
            
            if not password_is_valid:
                if attempts == input_login_attempts:
                    blocked = True

            msg = {
                "password_is_valid": password_is_valid,
                "blocked": blocked,
            }
            self.clientSocket.sendall(pickle.dumps(msg))

            if blocked:
                self.server_data.block_user_login(username)
                return False
            if password_is_valid:
                break

            attempts += 1

        # User info verification success.

        # Receive user UDP port.
        user_UDP_socket_port = self.clientSocket.recv(HEADER)
        user_UDP_socket_port = pickle.loads(user_UDP_socket_port)

        # Login the user (create an active user).
        login_success = self.login_user(username, user_UDP_socket_port)
        self.clientSocket.sendall(pickle.dumps(login_success))

        return login_success

    def login_user(self, username, user_UDP_socket_port):
        
        login_timestamp = self.convert_datetime_to_timestamp(datetime.now())

        new_active_user = {
            "username": username,
            "login_timestamp": login_timestamp,
            "UDP_socket_port": user_UDP_socket_port,
            "IP_address": self.clientAddress[0],
        }
        login_success = self.server_data.create_active_user(new_active_user)

        if login_success:
            print(f"{username} has logged in.")
            self.create_user_log(new_active_user)
        else:
            print(f"{username} has failed to login.")

        return login_success

    # ----------------------------------------------------------------
    # Helpers.
    # ----------------------------------------------------------------

    def create_user_log(self, active_user):
        with open("userlog.txt", "r") as stream:
            lines = stream.readlines()

        # Obtain next user sequence number.
        try:
            last_line = lines[-1]
        except IndexError as e:
            last_line = None

        next_seq_num = 1
        if last_line:
            last_seq_num = int(last_line.split(";")[0])
            next_seq_num = last_seq_num + 1

        # Obtain relevant active_user details. 
        timestamp = active_user["login_timestamp"]
        username = active_user["username"]
        IP_address = active_user["IP_address"]
        UDP_socket_port = active_user["UDP_socket_port"]

        with open("userlog.txt", "a", encoding="utf-8") as stream:
            stream.write(f"{next_seq_num}; {timestamp}; {username}; {IP_address}; {UDP_socket_port}\n")

    def delete_user_log(self, user):
        with open("userlog.txt", "r") as stream:
            lines = stream.readlines()

        # Remove the relevant user.
        removed_line = ""
        for line in lines:
            log_line = re.split(r"; ", line)
            log_username = log_line[2]
            if log_username == user:
                removed_line = line
                break

        lines.remove(removed_line)

        # Update seq numbers.
        seq_number = 1
        for i, line in enumerate(lines):
            lines[i] = re.sub(r"^\d+", str(seq_number), line, count=1)
            seq_number += 1

        with open("userlog.txt", "w") as stream:
            for line in lines:
                stream.write(line)

    def create_message_log(self, broadcast_msg):
        message_id = broadcast_msg["message_id"]
        timestamp = self.convert_datetime_to_timestamp(broadcast_msg["timestamp"])
        username = broadcast_msg["username"]
        message = broadcast_msg["message"]

        with open("messagelog.txt", "a") as stream:
            stream.write(f"{message_id}; {timestamp}; {username}; {message}\n")

    def convert_datetime_to_timestamp(self, date_time):
        day = date_time.strftime("%d")
        month = date_time.strftime("%b")
        year = date_time.strftime("%Y")
        hour = date_time.strftime("%H")
        minute = date_time.strftime("%M")
        seconds = date_time.strftime("%S")

        return f"{day} {month} {year} {hour}:{minute}:{seconds}"

# ----------------------------------------------------------------
# Start function.
# ----------------------------------------------------------------

def start():
    """Starts the server, accepting new TCP connections.
    """
    server_data = ServerData()

    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind(ADDRESS)
    serverSocket.listen()

    print("Server is now running")

    while True:
        clientSockt, clientAddress = serverSocket.accept()
        clientThread = ClientThread(clientAddress, clientSockt, server_data)
        clientThread.start()

# ----------------------------------------------------------------
# Main function.
# ----------------------------------------------------------------

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 server.py <login-attempts>")
        sys.exit(1)

    # Check login_attempts is of type int.
    if not validate.validate_login_attempts_number(sys.argv[1]):
        print("<login-attempts> must be a number between 1 and 5")
        sys.exit(1)

    # Start server.
    start()

