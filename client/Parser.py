#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import sys
from termcolor import colored

reload(sys)
sys.setdefaultencoding('utf8')

def color_parser(string_data):
        str_string_data = string_data
        string_data = list(string_data)
        get_out = False
        nickname_chars = []
        trunc_message = []
        red_nickname = ""
        blue_nickname = ""
        nickname = ""
        message_to_send = ""
        arobase = False
        
        for index, caract in enumerate(string_data):
                if caract == (u"[").encode("utf-8") or caract == (u"@").encode("utf-8") and u"server_message".encode("utf-8") not in str_string_data:

                        if caract == (u"@").encode("utf-8"):
                                arobase = True

                        while index < len(string_data):
                                if string_data[index] == (u"]").encode("utf-8") or string_data[index] == (u":").encode("utf-8"):
                                        get_out = True

                                else:
                                        nickname_chars.append(string_data[index])

                                index = index + 1

                                if get_out:
                                        if arobase:
                                                break

                                        nickname_chars.append("]")
                                        break
                
                else:
                        red_message_serv = ""
                        red_message = str_string_data.replace("server_message", "")
                        red_message = colored(red_message, "red")
                        
                        return red_message_serv, red_message

                if get_out:
                        trunc_message = string_data[index:len(string_data)]
                        break

        nickname = "".join(nickname_chars)
        message_to_send = "".join(trunc_message)
        
        red_nickname = colored(nickname, "blue")
        blue_message = colored(message_to_send, "red")

        return red_nickname, blue_message

