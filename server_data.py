
import time

class ServerData():
    def __init__(self):
        self.registered_users = []
        self.active_users = []
        self.broadcasted_messages = []
        self.chat_rooms = []

        # Automatically load credentialls when instantiating this class.
        self.load_credentials()

        self.reset_user_log_file()
        self.reset_message_log_file()
    
    def __str__(self):
        return str(self.__dict__)

    def load_credentials(self):
        """Load user data from credentials.txt.
        """
        with open("credentials.txt", "r", encoding="utf-8") as stream:
            for line in stream:
                username, password = line.split()
                self.registered_users.append({
                    "username": username,
                    "password": password,
                    "recent_time_blocked": None,
                })

    def reset_user_log_file(self):
        open("userlog.txt", "w").close()

    def reset_message_log_file(self):
        open("messagelog.txt", "w").close()

    # ----------------------------------------------------------------
    # Authentification methods.
    # ----------------------------------------------------------------

    def valid_username(self, username):
        for user in self.registered_users:
            if username == user["username"]:
                return True
        return False

    def valid_user(self, username, password):
        for user in self.registered_users:
            if username == user["username"] and password == user["password"]:
                return True
        return False

    def user_is_blocked(self, username):
        """Returns False if more than 10 seconds have elapsed since the user has been
           blocked.
        """
        user = self.get_registered_user_details(username)
        if user and user["recent_time_blocked"]:
            if time.time() - user["recent_time_blocked"] <= 10:
                return True
        return False

    def block_user_login(self, username):
        for user in self.registered_users:
            if username == user["username"]:
                user["recent_time_blocked"] = time.time()

    # ----------------------------------------------------------------
    # Registered user methods.
    # ----------------------------------------------------------------

    def get_registered_user_details(self, username):
        for user in self.registered_users:
            if username == user["username"]:
                return user

    # ----------------------------------------------------------------
    # Active user methods.
    # ----------------------------------------------------------------

    def create_active_user(self, active_user):
        if self.is_active_user(active_user["username"]):
            return False

        self.active_users.append(active_user)
        return True

    def is_active_user(self, username):
        for user in self.active_users:
            if username == user["username"]:
                return True
        return False

    def get_active_user_details(self, username):
        for user in self.active_users:
            if username == user["username"]:
                return user

    def delete_active_user(self, username):
        user = self.get_active_user_details(username)
        self.active_users.remove(user)

    # ----------------------------------------------------------------
    # Broadcasted messages methods.
    # ----------------------------------------------------------------

    def create_broadcasted_message(self, broadcast_msg):
        self.broadcasted_messages.append(broadcast_msg)

    # ----------------------------------------------------------------
    # Chat room methods.
    # ----------------------------------------------------------------

    def create_chat_room(self, room_id, members):
        chat_room = {
            "room_id": room_id,
            "members": members,
            "messages": [],
        }
        self.chat_rooms.append(chat_room)


    # ----------------------------------------------------------------
    # Getters
    # ----------------------------------------------------------------

    def get_registered_users(self):
        return self.registered_users

    def get_active_users(self):
        return self.active_users

    def get_broadcasted_messages(self):
        return self.broadcasted_messages

    def get_chat_rooms(self):
        return self.chat_rooms
