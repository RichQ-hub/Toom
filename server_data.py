
import time

class ServerData():
    def __init__(self):
        self.registered_users = []
        self.active_users = []
        self.broadcast_messages = []
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
    # Broadcast messages methods.
    # ----------------------------------------------------------------

    def create_broadcast_message(self, user, message, message_id, timestamp):
        broadcast_message = {
            "username": user,
            "message_id": message_id,
            "timestamp": timestamp,
            "message": message,
        }
        self.broadcast_messages.append(broadcast_message)

    def generate_broadcast_message_id(self):
        message_id = 1
        if len(self.broadcast_messages) != 0:
            message_id = self.broadcast_messages[-1]["message_id"] + 1
        return message_id

    def get_recent_broadcast_messages(self, datetime):
        return list(filter(lambda bm: bm["timestamp"] > datetime, self.broadcast_messages))

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
    
    def create_chat_room_message(self, room_id, user, message, message_id, timestamp):
        chat_room_message = {
            "username": user,
            "message_id": message_id,
            "timestamp": timestamp,
            "message": message,
        }
        chat_room = self.get_chat_room_details(room_id)
        chat_room["messages"].append(chat_room_message)

    def generate_chat_room_id(self):
        room_id = 1
        if len(self.chat_rooms) != 0:
            room_id = self.chat_rooms[-1]["room_id"] + 1
        return room_id

    def generate_chat_room_message_id(self, room_id):
        chat_room = self.get_chat_room_details(room_id)
        message_id = 1
        if len(chat_room["messages"]) != 0:
            message_id = chat_room["messages"][-1]["message_id"] + 1
        return message_id

    def get_chat_room_id_by_users(self, usernames):
        for room in self.chat_rooms:
            if set(room["members"]) == set(usernames):
                return room["room_id"]
        return None

    def get_chat_room_details(self, room_id):
        chat_room_details = list(filter(lambda room: room['room_id'] == room_id, self.chat_rooms))
        return chat_room_details[0]

    def get_chat_room_ids(self):
        return list(map(lambda room: room["room_id"], self.chat_rooms))

    def get_chat_rooms_for_user(self, user):
        return list(filter(lambda room: user in room["members"], self.chat_rooms))

    def get_recent_chat_room_messages(self, datetime, room_id):
        chat_room_details = self.get_chat_room_details(room_id)
        return list(filter(lambda sm: sm["timestamp"] > datetime, chat_room_details["messages"]))

    # ----------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------

    def get_inactive_users(self, users):
        active_usernames = self.get_active_usernames()
        registered_usernames = self.get_registered_usernames()
        return list(filter(lambda user: user in registered_usernames and user not in active_usernames, users))

    def get_unknown_users(self, users):
        registered_usernames = self.get_registered_usernames()
        return list(filter(lambda user: user not in registered_usernames, users))

    def get_active_usernames(self):
        return list(map(lambda user: user['username'], self.active_users))

    def get_registered_usernames(self):
        return list(map(lambda user: user['username'], self.registered_users))

    # ----------------------------------------------------------------
    # Getters
    # ----------------------------------------------------------------

    def get_registered_users(self):
        return self.registered_users

    def get_active_users(self):
        return self.active_users

    def get_broadcast_messages(self):
        return self.broadcast_messages

    def get_chat_rooms(self):
        return self.chat_rooms
