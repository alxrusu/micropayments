'''This script will serve as a broker server in the micropayments scheme'''
import socket
import ssl
import json
import os
import Crypto.PublicKey.RSA as RSA
from datetime import datetime
from utils import *
from threading import Thread


class Broker:

    HOST = ''   # Symbolic name, meaning all available interfaces
    PORT = 0    # Arbitrary non-privileged port

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
        self.identity = self.PORT
        self.vendors = dict()
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

    def deal_with_client(self, connstream, port):
        data = connstream.read()

        print data
        request = json.loads(data)
        if request['Request'] == 'Certificate':
            userdata = request['Data']
            user_identity = userdata['Identity']
            user_public_key = userdata['KeyUser']
            publickey = self.key.publickey()
            payword_json = {"Broker": str(self.identity),
                            "User": str(user_identity),
                            "UserIP": str(self.addr),
                            "KeyBroker": str(publickey.exportKey()),
                            "KeyUser": str(user_public_key),
                            "ExpirationDate": str(datetime.now()),
                            "Info": str(self.credit)}
            cert_sig = generateSignature(
                payword_json, self.key)
            print "\n\n" + json.dumps(payword_json) + "\n\n"
            connstream.send(json.dumps(
                {'Response': 'OK',
                 'Data': payword_json,
                 'Signature': cert_sig}).encode('utf-8'))

        elif request['Request'] == 'Redeem':
            data = request['Data']
            commit = data['Commit']

            cert = commit['Certificate']
            cert_sig = commit['CertificateSignature']

            if cert['Broker'] != str(self.identity):
                connstream.send(
                    json.dumps({'Response': 'Error',
                                'Data': 'Invalid Broker',
                                'Signature': ''}).encode('utf-8'))
            elif cert['KeyBroker'] != str(self.key.publickey().exportKey()):
                connstream.send(
                    json.dumps({'Response': 'Error',
                                'Data': 'Forged Key',
                                'Signature': ''}).encode('utf-8'))
            elif not verifySignature(cert, self.key, cert_sig):
                connstream.send(
                    json.dumps({'Response': 'Error',
                                'Data': 'Invalid Signature',
                                'Signature': ''}).encode('utf-8'))
            else:
                if port not in self.vendors:
                    self.vendors[port] = list()
                if commit['HashRoot'] in self.vendors[port]:
                    connstream.send(
                        json.dumps({'Response': 'Error',
                                    'Data': 'Already Redeemed',
                                    'Signature': ''}).encode('utf-8'))
                else:
                    self.vendors[port].append(commit['HashRoot'])
                    connstream.send(
                        json.dumps({'Response': 'Error',
                                    'Data': 'Redeem Successful',
                                    'Signature': ''}).encode('utf-8'))

        self.ssl_disconnect()

    def ssl_accept(self):
        self.conn, self.addr = self.soc.accept()

        try:
            self.connstream = ssl.wrap_socket(
                self.conn,
                server_side=True,
                certfile=ssl_certfile,
                keyfile=ssl_keyfile,
                ssl_version=ssl.PROTOCOL_TLSv1
            )
            print "SSL wrap succeeded for sever"
        except socket.error, msg:
            if (msg is not None):
                print "SSL wrap failed for server: " +\
                    str(msg[0]) + " Message " + msg[1]
        return True

    def ssl_disconnect(self):
        self.connstream.close()

    def serve(self):
        while True:
            self.ssl_accept()
            thread = Thread(target=self.deal_with_client,
                            args=(self.connstream, self.addr[1]))
            thread.start()

    def runcmd(self):
        pass


if __name__ == "__main__":

    broker = Broker(9043)

    broker.serve()
