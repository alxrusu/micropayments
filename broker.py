'''This script will serve as a broker server in the micropayments scheme'''
import sys
import socket
import ssl
import json
import hashlib
import os
import Crypto.PublicKey.RSA as RSA
from datetime import datetime
from utils import *


class Broker:

    HOST = ''   # Symbolic name, meaning all available interfaces
    PORT = 0    # Arbitrary non-privileged port
    ssl_certfile = "cert.pem"
    ssl_keyfile = "key.pem"

    def buildSocket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print 'Socket created'
        except socket.error, msg:
            print 'Failed to create socket Error code: ' +\
                str(msg[0]) + ', Error message: ' + msg[1]
        return s

    def __init__(self, port=9043):
        self.PORT = port
        self.soc = self.buildSocket()
        self.key = RSA.generate(1024, os.urandom)
        self.credit = 6
        err = 0
        msg = None
        try:
            self.soc.bind((self.HOST, self.PORT))
        except socket.error, msg:
            print "Bind failed in server: "\
                + str(msg[0]) + " Message " + msg[1]
            err = 1
        if not err:
            try:
                self.soc.listen(10)
            except socket.error, msg:
                print "Listen failed: " + str(msg[0]) + " Message " + msg[1]
                err = 1

    def deal_with_client(self, connstream):
        data = connstream.read()

        while data:
            try:
                request = json.loads(data)
                if request['Request'] == 'Certificate':
                    userdata = request['Data']
                    user_identity = userdata['identity']
                    user_public_key = userdata['KeyUser']
                    publickey = self.key.publickey()
                    payword_json = {"Broker": str(self.identiy),
                                    "User": str(user_identity),
                                    "UserIP": str(self.addr),
                                    "KeyBroker": str(publickey.exportKey()),
                                    "KeyUser": str(user_public_key),
                                    "ExpirationDate": str(datetime.now()),
                                    "Info": str(self.credit)}
                    print sign_message(json.dumps(payword_json))
                elif request['Request'] == 'Redeem':
                    userdata = request['Data']
                    signature = request['Signature']
                    commit = userdata['Commit']
                    last_commit = userdata['LastCommit']
                    last_commit_index = userdata['LastCommitIndex']

                    vendor = commit['Vendor']
                    cert = commit['Certificate']
                    cert_sig = commit['CertificateSignature']
                    hash_root = commit['HashRoot']
                    time = commit['Time']
                    length = commit['Info']

                    # broker = cert['Broker']
                    # user = cert['User']
                    # userIP = cert['UserIP']
                    # keyBroker = cert['KeyBroker']
                    # keyUser = cert['KeyUser']
                    # expirationDate = cert['ExpirationDate']
                    # info = cert['Info']

                    if cert_sig != sign_message(json.dumps(cert)) or\
                       signature != sign_message(json.dumps(userdata)):
                        print "Invalid signature"
                    else:
                        print "Checking hashes"

                        print "Hashes ok"
                    
            except:
                print "Malformed packed"

            data = connstream.read()

    def ssl_accept(self):
        self.conn, self.addr = self.soc.accept()

        try:
            self.connstream = ssl.wrap_socket(
                self.conn,
                server_side=True,
                certfile=self.ssl_certfile,
                keyfile=self.ssl_keyfile,
                ssl_version=ssl.PROTOCOL_TLSv1
            )
            print "SSL wrap succeeded for sever"
        except socket.error, msg:
            if (msg is not None):
                print "SSL wrap failed for server: " +\
                    str(msg[0]) + " Message " + msg[1]
        return True

    def ssl_disconnect(self):
        self.soc.close()
        self.connstream.close()

    def serve(self):

        self.ssl_accept()

        while True:
            data = self.connstream.recv(1024)
            if data:
                print "server: " + data
            else:
                break

        self.ssl_disconnect()

    def runcmd(self):
        pass


if __name__ == "__main__":

    broker = Broker(10000)
    print broker.sign_message("asdf")
    sys.exit()
    broker.serve()
