#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback

#Imports required for encryption
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

DIR = "C:/Users/Emy/Desktop/seguranca/"

def encryption(arg_publickey, arg_cleartext):
    encryptor = PKCS1_OAEP.new(arg_publickey)
    ciphertext = encryptor.encrypt(arg_cleartext)
    return base64.b64encode(ciphertext)

def decryption(arg_privatekey, arg_b64text):
    decoded_data = base64.b64decode(arg_b64text)
    decryptor = PKCS1_OAEP.new(arg_privatekey)
    decrypted = decryptor.decrypt(decoded_data)
    return decrypted

PUBKEY = DIR + "pub.pubkey"
PRIVKEY = DIR + "priv.privkey"

class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def run(self):
        lis = []
        lis.append(self.receive)
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        chunck = s
                        f_privkey = open(PRIVKEY, 'rb')
                        privatekey = RSA.importKey(f_privkey.read())
                        cleartext2 = decryption(privatekey, chunck)                        
                        print(cleartext2.decode() + '\n>>')

                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):
    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg):
        sent = self.sock.send(msg)
        # print "Sent\n"

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            host = input("Enter the server IP \n>>")
            port = int(input("Enter the server Destination Port\n>>"))
        except EOFError:
            print("Error")
            return 1

        print("Connecting\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")
        user_name = input("Enter the User Name to be Used\n>>")
        receive = self.sock
        time.sleep(1)
        srv = Server()
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service")
        srv.start()
        while 1:
            # print "Waiting for message\n"
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue
            # print "Sending\n"
            msg = user_name + ': ' + msg
            data = msg.encode()
            
            f_pubkey = open(PUBKEY, 'rb')
            publickey = RSA.importKey(f_pubkey.read())
            ciphertext = encryption(publickey, data)
            
            self.client(host, port, ciphertext)
        return (1)


if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()
