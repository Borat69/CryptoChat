#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import sys

reload(sys)
sys.setdefaultencoding('utf8')


COMMANDS_LIST = ["$get_nicknames_up", "$get_pop", "$get_all_infos", "$get_skull", "$get_skull_diffuse"]
COMMANDS_LIST_HELP = ["$get_nicknames_up: get all nicknames of connected friends\n", "$get_pop @nickname: close the connection of a friend\n"]


def get_commands():
        return COMMANDS_LIST_HELP


def check_arobase(data_content):
        string_content = ("u" + str(data_content)).encode("utf-8")
        if u"$get_".encode("utf-8") in string_content or u"$help".encode("utf-8") in string_content:
                return False
        
        if u"@".encode("utf-8") in string_content:
                return True

        return False


def check_command(data_content):
        string_content = ("u" + str(data_content)).encode("utf-8")
        
        if u"$help".encode("utf-8") in string_content:
                return True
        
        if u"$get_".encode("utf-8") in string_content:
                return True

        return False


def command_parser(decrypted_message):
        list_decrypted_message = list(decrypted_message)
        command_chars = []
        get_out = False
        
        for index, caract in enumerate(list_decrypted_message):
                if caract == ("$"):

                        while index < len(list_decrypted_message):
                                if list_decrypted_message[index] == (" "):
                                        get_out = True
                                        break

                                else:
                                        command_chars.append(list_decrypted_message[index])
                                        
                                index = index + 1

                if get_out:
                        break
                
        command = "".join(command_chars)
        print "command: " + str(command)

        if u"$help".encode("utf-8") == command:
                command = "$help"
                return command
                
        for comm in COMMANDS_LIST:
                if command in comm:
                        return command 
                      
        if command not in COMMANDS_LIST:
                return "Unknown"
                              
        return command       


def arobase_parser(decrypted_message, is_arobase_message):
        list_decrypted_message = list(decrypted_message)
        nickname_chars = []
        first_space = True
        get_out = False
        trunc_message = []

        for index, caract in enumerate(list_decrypted_message):
                if caract == (u"@").encode("utf-8"):
                        arrobase_num = index

                        while index < len(list_decrypted_message):
                                if list_decrypted_message[index] == (u" ").encode("utf-8"):
                                        get_out = True
                                        break

                                else:
                                        nickname_chars.append(list_decrypted_message[index])

                                index = index + 1

                if get_out:
                        if is_arobase_message:
                                trunc_message = list_decrypted_message[index:len(list_decrypted_message)]
                                break

                        nickname = "".join(nickname_chars)

                        return nickname, None

        nickname = "".join(nickname_chars)
        message_to_send = "".join(trunc_message)
        
        return nickname, message_to_send
