#!/usr/bin/python
# -*- coding: utf-8 -*-

# *********************************************** Crypto chat by boris et manu *********************************************************


from __future__ import unicode_literals

import sys
import socket
import select
from Cipher import *
from Parser import arobase_parser
import pickle
import os
from glob import glob
import ast
import signal
import hashlib
from os.path import expanduser

reload(sys)
sys.setdefaultencoding('utf8')


# Variables globales
HOST = ''
SOCKET_LIST = []
RECV_BUFFER = 262144
PORT = 9009
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

def open_room():
    port = raw_input("Which port? ")
    return port

def check_arobase(data_content):
    string_content = ("u" + str(data_content)).encode("utf-8")
    if u"@".encode("utf-8") in string_content:
        return True

    return False

# Fonction permettant de transmettre un message envoyé à tous les clients connectés
def transmit(server_socket, sock, message, ip, is_message_client):
    
    # Message en provenance d'un client
    if is_message_client:
        decrypted_message = decrypt_message(ip, message, IP_SYM_KEY_DICT) # Le message envoyé par le socket est déchiffré
        
        if check_arobase(decrypted_message):
               
            arobase_parse = arobase_parser(decrypted_message)
            nickname = arobase_parse[0]
            message_to_send = arobase_parse[1]
            print "nickname: " + nickname
            print "trunc message: " + message_to_send
            print "liste nicknames: " + str(IP_NICKNAME)
            
            for ip_elem in IP_NICKNAME:
                if IP_NICKNAME[ip_elem] == nickname:
                    ip_cipher_addr = ip_elem
                    cipher_socket = IP_SOCKET_DICT[ip_elem] # Socket désigné par le nickname et l'adresse ip associée
                    message_to_send = IP_NICKNAME[ip] + " to you:" + message_to_send
                    hex_ciphertext = encrypt_message(ip_cipher_addr, message_to_send, IP_SYM_KEY_DICT)
                    cipher_socket.send(hex_ciphertext)
                    
                    break
                
            if nickname not in IP_NICKNAME.values():    
                ip_cipher_addr = ip_elem
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
                        
    # Message en provenance du serveur
    else: 
        for socket in SOCKET_LIST:

            # Pas besoin de déchiffrement car c'est un message en provenance du serveur (déjà sous format string)
            if socket != server_socket and socket != sock: #sock != client_socket pour ne pas envoyer le message au client venant de se connecter
                try : 		
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


def adding_nickname(new_nickname):
    name = str(new_nickname)
    f = open("nickname", "a")
    f.write(name)
    
    return


def chat_server():
    # Presentation du chat
    port = open_room()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #pour la connection par internet changer AF_INET en AF_INET6
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, int(port)))
    server_socket.listen(10)

    #add server socket object to the list of readable connections
    SOCKET_LIST.append(server_socket)
    #IP_SOCKET_DICT["server_socket"] = server_socket
    print "Crypted chat server started on port " + str(int(port))

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
                    
                IP_FIRST_CONNECTION_DICT[ip_client] = True # Premiere connexion
                
                #print "listes des ips connectes: " + str(IP_SOCKET_DICT) 
                #client_name = sock.gethostname()
                print "Client (%s, %s) connected " % addr
                
                # Checker dans la liste des sockets si il n'y a pas des redondances et si c'est le cas, tout virer sauf le dernier
                # Permet de gérer les connexions et déconnexion d'un meme client
                print "IP_SOCKET_DICT " + str(IP_SOCKET_DICT)
                print "server_socket: " + str(server_socket)
                print "socket client: " + str(sockfd)
                # Gros probleme avec ce code, si le client se reconnecte, les messages ne sont plus envoyés (resolu)

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
            
                #sending public key to the client
                #send_public_key = pickle.dumps(public_key)
                sockfd.send(public_key.exportKey())
                is_message_client = False
                transmit(server_socket, sockfd, "[%s:%s] entered our chatting room\n" % addr, None, is_message_client)

            # a message from a client, not a new connection
            else:
                # process data received from client,
                try:
                    #meme chose ici decoder avec la cle prive et renvoyer au client souhaité avec la clé publique correspondante
                    # receiving data from the socket.

                    data = sock.recv(RECV_BUFFER)
                    
                    if data:
                        
                        arobase_message = False
                        print "current addr: " + str(sock.getpeername())
                        curr_tuple = sock.getpeername()
                        curr_ip = curr_tuple[0]
                                                          
                        print "liste IP_SOCKET_DICT: " + str(IP_SOCKET_DICT)
                        
                        print "liste IP_FIRST CONNECTION: " + str(IP_FIRST_CONNECTION_DICT)                        
                        
                        for client_ip in IP_SOCKET_DICT:                        
                            if str(curr_ip) == str(client_ip) and IP_FIRST_CONNECTION_DICT[curr_ip] == False: #and arobase_message == False 
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
                                hex_enc_nickname = data[1056:len(data)]
                                
                                enc_sym_key = hex_enc_sym_key.decode("hex")
                                
                                # Déchiffrement de la clé symétrique
                                priv_key = get_priv_key(curr_ip)
                                sym_key = asym_decrypt(enc_sym_key, priv_key)
                                
                                
                                # Association de la clé symétrique et de l'IV à l'ip du client:
                                sym_key_iv_pair = [sym_key, IV]
                                
                                IP_SYM_KEY_DICT[curr_ip] = sym_key_iv_pair

                                # Déchiffrement du pseudo (nickname) et ajout de ce dernier dans une liste associée a l'ip
                                nickname = decrypt_message(curr_ip, hex_enc_nickname, IP_SYM_KEY_DICT)
                                IP_NICKNAME[curr_ip] = nickname
                                
                                print "nickname: " + str(nickname)
                                
                                IP_FIRST_CONNECTION_DICT[curr_ip] = False
                                
                                #if check_arobase(decrypted_message):
                                    #adding_nickname(decrypted_message)
                                    #NICKNAME_DICT[curr_ip] = decrypted_message
                                    #arobase_message = True
                                    
                                break            

                    else:
                        # remove the socket that's broken
                        if sock in SOCKET_LIST:
                            ip_tuple = sock.getpeername()
                            ip_addr = ip_tuple[0]
                            
                            del IP_SOCKET_DICT[ip_addr]                        
                            SOCKET_LIST.remove(sock)
                            
                            del IP_NICKNAME[ip_addr]
                        
                        # at this stage, no data means probably the connection has been broken
                        transmit(server_socket, sock, "Client (%s, %s) is offline\n" % addr, None, is_message_client)

                # exception
                except:
                    transmit(server_socket, sock, "Client (%s, %s) is offline\n" % addr, None, is_message_client)
                    continue
                
    server_socket.close()

if __name__ == "__main__":
    sys.exit(chat_server())





