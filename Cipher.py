#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto import Random
import random
import string
import pickle
import os
from glob import glob
import ast
import signal
import hashlib
from os.path import expanduser

reload(sys)
sys.setdefaultencoding('utf8')


# Renvoie la signature au format string pour pouvoir etre envoyée par socket
def get_pub_key_signature(text_signature, private_key):
    # le parametre K n'a pas de valeur pour le chiffrement RSA
    K = ""

    # hashage de la signature
    hash = SHA512.new(text_signature).digest()

    # Signature du hash avec la cle privee
    signature = private_key.sign(hash, K)

    return str(signature[0])


# Génère un string random pour la signature de la clé publique
def text_sign():
    text_signature = ""
    selected_char = ""
    alphabet = string.ascii_lowercase
    rand_number_lett = random.randint(0, 25)
    i = 0

    while i < 100:
        rand_number_choice = str(random.randint(1, 3))

        if rand_number_choice == "1":
            rand_number_lett = random.randint(0, 25)
            selected_char = alphabet[rand_number_lett]

        elif rand_number_choice == "2":
            rand_number_lett = random.randint(0, 25)
            selected_char = alphabet[rand_number_lett].upper()

        else:
            selected_char = str(random.randint(0, 9))

        text_signature += selected_char
        i += 1

    return text_signature


def AES_IV_KEY_generator():
    AES_key = Random.new().read(32)
    iv = Random.new().read(AES.block_size)

    return AES_key, iv


def rsa_keys_generator():
    random_generator = Random.new().read
    private_key = RSA.generate(4096, random_generator)
    public_key = private_key.publickey()

    return public_key, private_key

# Couche de chiffrement symétrique AES
def sym_encrypt(data, iv, AES_key):
    symetric_cipher = AES.new(AES_key , AES.MODE_CFB, iv)

    return symetric_cipher.encrypt(data)


def sym_decrypt(enc_data, iv, AES_key):
    symetric_cipher = AES.new(AES_key , AES.MODE_CFB, iv)

    return symetric_cipher.decrypt(enc_data)


def sym_auth_encrypt(data, iv, AES_key):
    symetric_cipher = AES.new(AES_key , AES.MODE_CFB, iv)

    return symetric_cipher.encrypt(data)


def sym_auth_decrypt(enc_data, iv, AES_key):
    symetric_cipher = AES.new(AES_key , AES.MODE_CFB, iv)

    return symetric_cipher.decrypt(enc_data)


# Chiffrement asymétrique RSA
def asym_encrypt(sym_key, pub_key):
    asym_cipher = PKCS1_OAEP.new(pub_key)

    return asym_cipher.encrypt(sym_key)


def asym_auth_encrypt(sym_key, pub_key):
    asym_cipher = PKCS1_OAEP.new(pub_key)

    return asym_cipher.encrypt(sym_key)


def asym_decrypt(enc_sym_key, priv_key):
    asym_cipher = PKCS1_OAEP.new(priv_key)

    return asym_cipher.decrypt(enc_sym_key)


def asym_auth_decrypt(enc_sym_key, priv_key):
    asym_cipher = PKCS1_OAEP.new(priv_key)

    return asym_cipher.decrypt(enc_sym_key)


def socket_message(str_message, iv, AES_key):
    cipher_text = sym_encrypt(str_message, iv, AES_key)
    hex_cipher_text = cipher_text.encode("hex").upper()

    return hex_cipher_text
    

def socket_auth_message(str_message, iv, AES_key):
    cipher_text = sym_auth_encrypt(str_message, iv, AES_key)
    hex_cipher_text = cipher_text.encode("hex").upper()

    return hex_cipher_text


def string_socket_message(hex_enc_data, iv, AES_key):
    enc_data = hex_enc_data.decode("hex")
    message = sym_decrypt(enc_data, iv, AES_key)
    str_message = str(message)

    return str_message

def string_socket_auth_message(hex_enc_data, iv, AES_key):
    enc_data = hex_enc_data.decode("hex")
    message = sym_auth_decrypt(enc_data, iv, AES_key)
    str_message = str(message)

    return str_message


def generate_keys(ip, auth):
    rsa_keys = rsa_keys_generator()
    private_key = rsa_keys[1]
    public_key = rsa_keys[0]

    if auth:
        folder_name = "client_auth_" + str(ip)

    else:
        folder_name = "client_" + str(ip)

    folder_creation_command = "mkdir " + folder_name
    os.system(folder_creation_command)

    file_priv_name = "private_key.pem"
    file_priv_creation_command = "touch " + folder_name + "/" + file_priv_name
    priv_key_path =  folder_name + "/" + file_priv_name
    os.system(file_priv_creation_command)

    # exporting the key on a PEM file
    #file_key_name = "prv" + str(client_id) + ".pem"
    #file_key = open(file_key_name, "w")

    file_priv_key = open(priv_key_path, "w")
    file_priv_key.write(private_key.exportKey("PEM"))
    file_priv_key.close

    file_pub_name = "public_key.pub"
    file_pub_creation_command = "touch " + folder_name + "/" + file_pub_name
    pub_key_path = folder_name + "/" + file_pub_name
    os.system(file_pub_creation_command)

    file_pub_key = open(pub_key_path, "w")
    file_pub_key.write(public_key.exportKey())
    file_pub_key.close

    return public_key


def generate_auth_keys(ip, auth):
    rsa_keys = rsa_keys_generator()
    private_key = rsa_keys[1]
    public_key = rsa_keys[0]

    if auth:
        folder_name = "client_auth_" + str(ip)

    else:
        folder_name = "client_" + str(ip)

    folder_creation_command = "mkdir " + folder_name
    os.system(folder_creation_command)

    file_priv_name = "private_key.pem"
    file_priv_creation_command = "touch " + folder_name + "/" + file_priv_name
    priv_key_path =  folder_name + "/" + file_priv_name
    os.system(file_priv_creation_command)

    # exporting the key on a PEM file
    #file_key_name = "prv" + str(client_id) + ".pem"
    #file_key = open(file_key_name, "w")

    file_priv_key = open(priv_key_path, "w")
    file_priv_key.write(private_key.exportKey("PEM"))
    file_priv_key.close

    file_pub_name = "public_key.pub"
    file_pub_creation_command = "touch " + folder_name + "/" + file_pub_name
    pub_key_path = folder_name + "/" + file_pub_name
    os.system(file_pub_creation_command)

    file_pub_key = open(pub_key_path, "w")
    file_pub_key.write(public_key.exportKey())
    file_pub_key.close

    return public_key


def get_priv_key(ip, auth):
    if auth:
        priv_key_path = "client_auth_" + str(ip) + "/private_key.pem"

    else:
        priv_key_path = "client_" + str(ip) + "/private_key.pem"

    pv_key_file = open(priv_key_path, "r+")
    pv_key = RSA.importKey(pv_key_file.read())
    pv_key_file.close

    return pv_key


def get_auth_priv_key(ip, auth):
    if auth:
        priv_key_path = "client_auth_" + str(ip) + "/private_key.pem"

    else:
        priv_key_path = "client_" + str(ip) + "/private_key.pem"

    pv_key_file = open(priv_key_path, "r+")
    pv_key = RSA.importKey(pv_key_file.read())
    pv_key_file.close

    return pv_key


def get_pub_key(ip, auth):
    if auth:
        pub_key_path = "client_auth_" + str(ip) + "/public_key.pub"
    else:
        pub_key_path = "client_" + str(ip) + "/public_key.pub"

    pub_key_file = open(pub_key_path, "r+")
    pub_key = RSA.importKey(pub_key_file.read())
    pub_key_file.close

    return pub_key

# Est ce que la clé publique existe déjà pour cet adresse ip? Ou faut-il créer une nouvelle paire?
def check_pub_key(ip, auth):
    if auth:
        path_folder = "client_auth_" + str(ip)

    else:
        path_folder = "client_" + str(ip)

    if os.path.exists(path_folder):
        pub_key_path = path_folder + "/" + "public_key.pub"
        pub_key_file = open(pub_key_path, "r+")
        pub_key = RSA.importKey(pub_key_file.read())
        pub_key_file.close

        return pub_key

    else:
        if auth:
            new_pub_key = generate_keys(ip, True)

        else:
            new_pub_key = generate_keys(ip, False)

    return new_pub_key


def check_auth_pub_key(ip, auth):
    if auth:
        path_folder = "client_auth_" + str(ip)

    else:
        path_folder = "client_" + str(ip)

    if os.path.exists(path_folder):
        pub_key_path = path_folder + "/" + "public_key.pub"
        pub_key_file = open(pub_key_path, "r+")
        pub_key = RSA.importKey(pub_key_file.read())
        pub_key_file.close

        return pub_key

    else:
        if auth:
            new_pub_key = generate_auth_keys(ip, True)

        else:
            new_pub_key = generate_keys(ip, False)

    return new_pub_key


# Déchiffre un message recu sous format hexadécimal
# Reçoit en parametre l'ip du client, les données hexadecimales et le dictionnaire des clés symétriques avec l'ip du client comme clé
def decrypt_message(ip, hex_enc_data, dict_key_iv):
    list_sym_key_iv = dict_key_iv[ip]
    sym_key = list_sym_key_iv[0]
    IV = list_sym_key_iv[1]

    str_decrypted_message = string_socket_message(hex_enc_data, IV, sym_key)

    return str_decrypted_message


# Chiffre un message sous format string et l'encode en hexadécimal
def encrypt_message(ip, data, dict_key_iv, auth):
    list_sym_key_iv = dict_key_iv[ip]
    sym_key = list_sym_key_iv[0]
    IV = list_sym_key_iv[1]  
    pub_key = get_pub_key(ip, auth)

    hex_ciphertext = socket_message(str(data), IV, sym_key)

    return hex_ciphertext

# Redondance des fonctions pour l'authentification afin que ce soit thread safe
def decrypt_auth_message(ip, hex_enc_data, dict_key_iv):
    list_sym_key_iv = dict_key_iv[ip]
    sym_key = list_sym_key_iv[0]
    IV = list_sym_key_iv[1]

    str_decrypted_message = string_socket_auth_message(hex_enc_data, IV, sym_key)

    return str_decrypted_message


# Chiffre un message sous format string et l'encode en hexadécimal
def encrypt_auth_message(ip, data, dict_key_iv, auth):
    list_sym_key_iv = dict_key_iv[ip]
    sym_key = list_sym_key_iv[0]
    IV = list_sym_key_iv[1]  
    pub_key = get_pub_key(ip, auth)

    hex_ciphertext = socket_auth_message(str(data), IV, sym_key)

    return hex_ciphertext