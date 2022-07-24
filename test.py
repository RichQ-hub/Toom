from datetime import datetime
import pprint
import pickle
import sys
import textwrap
import time
import inspect

class Data():
    def __init__(self):
        self.registered_users = []
        self.active_users = []

        # Automatically load credentialls when instantiating this class.
        self.load_credentials()
    
    def __str__(self):
        return str(self.__dict__)

    def load_credentials(self):
        with open("credentials.txt", "r", encoding="utf-8") as stream:
            for line in stream:
                username, password = line.split()
                self.registered_users.append({
                    "username": username,
                    "password": password,
                })

    # ----------------------------------------------------------------
    # Getters
    # ----------------------------------------------------------------
    def get_registered_users(self):
        return self.registered_users

    def get_active_users(self):
        return self.active_users

# date = datetime.now()
# day = date.strftime("%d")
# month = date.strftime("%b")
# year = date.strftime("%Y")
# hour = date.strftime("%H")
# minute = date.strftime("%M")
# seconds = date.strftime("%S")

# print(f"{day} {month} {year} {hour}:{minute}:{seconds}")

ok = ["apples", "bees", "juice"]

ok_list = ""
for e in ok:
    ok_list += f"     > {e}\n"

test = """
[OUT]: Response ========================
mate has successfully logged out
elements:
{elements}
========================================
""".format(elements = ok_list)

test = textwrap.dedent(test)

print(test)

