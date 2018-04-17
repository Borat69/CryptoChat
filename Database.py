#!/usr/bin/python
# -*- coding: utf-8 -*-

import mysql.connector
import random
import string
from Crypto.Hash import SHA512		
import ast


class Database():

    def __init__(self):
        self.passwd_file = "passwd.txt"
        self.database_file = "citadel_db"

        with open(self.database_file, "r") as db:
            content = db.read()
            users = ast.literal_eval(content)
            db.close()

        with open(self.passwd_file, "r") as db:
            content = db.read()
            users_list = ast.literal_eval(content)
            db.close()

        self.users = users_list
        self.get_db = users
        self.passwd = ""


    def __help(self):
        print ""
        print "  show_database or show_db: show the current database"
        print "  initialize or init: remove the database with only admin authentication"
        print "  check_user user or chk user: check if the choosen user is present"
        print "  add_user user or add user: add a new user to the database"
        print "  del_user user or del user: remove an user from the database"
        print "  quit or q: quit Citadel Database"
        print "  help or h: show commands"


    def __return_table(self, list_user):
        list_number = []
        i = 0
        marge_sup = ""
        marge_inf = ""
        space = 0
        str_space = ""
        max_char = ""
        curr_user = ""
        users = []
        max_space = ""
        spaces = []
        marge_dict = {}

        for user in list_user:
            list_number.append(len(user))

        max_char = max(list_number)

        if max_char%2 != 0:
            get_marge = max_char + 5

        else:
            get_marge = max_char + 4

        for user in list_user:
            user_marge = (get_marge - len(user))/2

            while space < user_marge:
                str_space += " "
                space += 1

            marge_dict[user] = str_space
            curr_user = str_space + str(user) + str_space
            users.append(len(curr_user))

        max_char = max(users)

        i = 0
        while i < max_char + 2:
            marge_sup += "="
            i += 1

        marge_inf = marge_sup

        print "  " + marge_sup

        for user in list_user:
            new_marge = (max_char - len(user))/2

            i = 0
            str_space = ""
            while i < new_marge:
                str_space += " "
                i += 1

            if len(user)%2 != 0:
                print "  |" + str_space + str(user) + str_space + " |"

            else:
                print "  |" + str_space + str(user) + str_space + "|"
                  
            print "  " + marge_inf


    # Génère un password random
    def rand_passwd(self, size):
        selected_char = ""
        rand_string = ""
        alphabet = string.ascii_lowercase
        rand_number_lett = random.randint(0, 25)
        i = 0

        while i < size:
            rand_number_choice = str(random.randint(1, 3))

            if rand_number_choice == "1":
                rand_number_lett = random.randint(0, 25)
                selected_char = alphabet[rand_number_lett]

            elif rand_number_choice == "2":
                rand_number_lett = random.randint(0, 25)
                selected_char = alphabet[rand_number_lett].upper()

            else:
                selected_char = str(random.randint(0, 9))

            rand_string += selected_char
            i += 1

        return rand_string


    def base_login(self):
        self.passwd = self.rand_passwd(10)
        hash_passwd = SHA512.new(self.passwd).digest()

        self.users.clear()
        self.users["admin"] = self.passwd

        with open(self.passwd_file, "w") as p_file:
            p_file.write(str(self.users))
            p_file.close()

        self.get_db.clear()
        self.get_db["admin"] = hash_passwd
        with open(self.database_file, "w") as db:
            db.write(str(self.get_db))
            db.close()


    # Regarder si le password et le nickname correspondent
    def check_user(self, nickname, password, from_server):
        with open(self.database_file, "r") as db:
            str_check = db.read()
            check = ast.literal_eval(str_check)
            db.close()

        hash_passwd = SHA512.new(password).digest()

        if not from_server:
            if check.has_key(nickname):
                return True

            else:
                return False

        else:
            if check[nickname] == hash_passwd:
                return True

            else:
                return False


    # Seul les admins peuvent ajouter des users dans la base de données et en supprimer
    def del_user(self, user):
        if self.get_db.has_key(user):
            if str(user) == "admin":
                print""
                print "  impossible de supprimer le compte admin"

            else:
                del self.get_db[user]
                del self.users[user]

                with open(self.database_file, "w") as db:
                    db.write(str(self.get_db))
                    db.close()

                with open(self.passwd_file, "w") as p_file:
                    p_file.write(str(self.users))
                    p_file.close()

                print ""
                print "  " + str(user) + " a bien ete supprime de la base de donnees"

        else:
            print ""
            print "  " + str(user) + " est introuvable"


    def add_user(self, user):
        if self.get_db.has_key(user):
            print ""
            print "  " + str(user) + " existe deja, voulez vous le remplacer? o/n"
            rep = raw_input("> ")

            if str(rep.upper()) == "O":
                pass

            else:
                return

        password = self.rand_passwd(10)
        print ""
        print "  Mot de passe pour " + str(user) + ": " + str(password)

        hash_passwd = SHA512.new(password).digest()
        self.get_db[user] = hash_passwd 
        self.users[user] = password

        with open(self.database_file, "w") as db:
            db.write(str(self.get_db))
            db.close()            

        with open(self.passwd_file, "w") as p_file:
            p_file.write(str(self.users))
            p_file.close()

        print "  " + str(user) + " a bien ete ajoute dans la base de donnees"
        print "  Veuillez transmettre le mot de passe et le supprimer du fichier passwd.txt apres"


    def __get_nickname(self, command, check_user):
        com = str(command)

        if not check_user:
            comm = com[8:len(com)]

        else:
            comm = com[10:len(com)]

        nickname = []
        str_nickname = ""

        for char in comm:
            if char != " ":
                nickname.append(char)

        str_nickname = "".join(nickname)

        return str_nickname


    def show_menu(self):
        print ""
        print "Welcome to the Citadel Database"

        while True:
            print ""

            command = raw_input("citadel_db_@> ")

            try:
                if str(command) == "quit" or str(command) == "q":
                    print ""
                    print "Good bye!"
                    print ""
                    break

                elif str(command) == "help" or str(command) == "h":
                    self.__help()

                elif str(command) == "initialize" or str(command) == "init":
                    print "  Toute la base de donnees va etre reinitializee, etes vous sur? o/n"
                    rep = raw_input("> ")

                    if str(rep.upper()) == "O":
                        self.base_login()
                        print "  La base de donnees a ete remise a zero (Seul compte: admin)"

                elif "check_user" in str(command) or "chk" in str(command):
                    new_command = command.replace("chk", "check_user")

                    nickname = self.__get_nickname(new_command, True)

                    if self.check_user(nickname, None, False):
                        print ""
                        print "  " + str(nickname) + " est bien present dans la base de donnees"

                    else:
                        print ""
                        print "  " + str(nickname) + " n'a pas ete trouve"

                elif "add_user" in str(command) or "add" in str(command):

                    new_command = ""
                    if str(command).startswith("add_"):
                        new_command = str(command)

                    else:
                        new_command = command.replace("add", "add_user")

                    self.add_user(self.__get_nickname(new_command, False))

                elif "del_user" in str(command) or "del" in str(command):
                    
                    new_command = ""
                    if str(command).startswith("del_"):
                        new_command = str(command)

                    else:
                        new_command = command.replace("del", "del_user")

                    self.del_user(self.__get_nickname(new_command, False))

                elif str(command) == "show_database" or str(command) == "show_db":
                    print ""
                    self.__return_table(self.get_db)

                else:
                    print ""
                    print "  Unknown command " + "\"" + str(command) + "\""

            except Exception as e:
                print str(e)


if __name__ == "__main__":

    citadel_database = Database()
    citadel_database.show_menu()

