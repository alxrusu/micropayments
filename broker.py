'''This script will serve as a broker server in the micropayments scheme'''
import sys
import socket
import ssl
import json
import hashlib
import os
import Crypto.PublicKey.RSA as RSA
from datetime import datetime


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

    def sign_message(self, message):
        sha1 = hashlib.sha1()
        sha1.update(message)

        signature = self.key.sign(sha1.hexdigest(), '')
        return message + str(signature)

    def split_signature(self, message):
        rev = message[::-1]
        poz = rev.index("}")
        return (message[:len(message) - poz],
                message[len(message) - poz:])

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
                    print self.sign_message(json.dumps(payword_json))
                elif request['Request'] == 'Redeem':
                    userdata = request['Data']
                    commit = userdata['Commit']
                    last_commit = userdata['LastCommit']
                    last_commit_index = userdata['LastCommitIndex']
                    commit = self.split_signature(commit)

                    user_identity = userdata['identity']
                    user_public_key = userdata['KeyUser']
                    publickey = self.key.publickey()
                    response_json = {"Broker": str(self.identiy),
                                     "User": str(user_identity),
                                     "UserIP": str(self.addr),
                                     "KeyBroker": str(publickey.exportKey()),
                                     "KeyUser": str(user_public_key),
                                     "ExpirationDate": str(datetime.now()),
                                     "Info": str(self.credit)}
                    print self.sign_message(json.dumps(response_json))
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
