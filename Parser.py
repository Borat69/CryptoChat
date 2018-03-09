#!/usr/bin/python

def cipher_send(IP_NICKNAME, IP_SOCKET_DICT, decrypted_message,):
	if check_arobase(decrypted_message):
		nickname_chars = []
        nickname = ""
        
        list_decrypted_message = list(decrypted_message)
        
        print "dec message: " + str(list_decrypted_message)
        
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
        print "liste nicknames: " + str(IP_NICKNAME)
        
        for ip_elem in IP_NICKNAME:
            if IP_NICKNAME[ip_elem] == nickname:
                ip_cipher_addr = ip_elem
                cipher_socket = IP_SOCKET_DICT[ip_elem] # Socket désigné par le nickname et l'adresse ip associée
                message_to_send = IP_NICKNAME[ip] + " to [Me]" + message_to_send
                hex_ciphertext = encrypt_message(ip_cipher_addr, message_to_send)
                cipher_socket.send(hex_ciphertext)
                
                break
            
        if nickname not in IP_NICKNAME.values():    
            ip_cipher_addr = ip_elem
            hex_ciphertext = encrypt_message(ip_cipher_addr,nickname + " not found") # Sinon on renvoie un message d'erreur au socket envoyeur
            sock.send(hex_ciphertext)
        
        return # Permet de sortir de la fonction