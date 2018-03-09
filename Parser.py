#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import sys
from termcolor import colored
reload(sys)
sys.setdefaultencoding('utf8')

def color_parser(string_data):
        string_data = list(string_data)
        nickname_chars = []
        get_out = False
        trunc_mess = []
        
        for index, caract in enumerate(string_data):
                if caract == (u"[").encode("utf-8") or caract == ("@").encode("utf-8"):
                        while index < len(string_data):
                                if string_data[index] == (u"]").encode("utf-8") or string_data[index] == (u" ").encode("utf-8"):
                                        get_out = True
                                        break

                                else:
                                        nickname_chars.append(string_data[index])

                                index = index + 1

                        if get_out:
                                trunc_mess = string_data[index:len(string_data)]
                                break
                        
        nickname = "".join(nickname_chars)
        message_to_send = "".join(trunc_mess)
        
        red_nickname = colored(nickname, "red")
        blue_message = colored(message_to_send, "cyan")

        return red_nickname, blue_message


def arobase_parser(decrypted_message):
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
                        trunc_message = list_decrypted_message[index:len(list_decrypted_message)]
                        break

        nickname = "".join(nickname_chars)
        message_to_send = "".join(trunc_message)

        print "nickname: " + nickname
        print "trunc message: " + message_to_send
        
        return nickname, message_to_send
