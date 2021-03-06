'''This script will serve as a broker server in the micropayments scheme'''
import socket
import ssl
import json
import os
import sys
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
            print 'Broker Server started!'
        except socket.error, msg:
            print 'Failed to create socket Error code: ' +\
                str(msg[0]) + ', Error message: ' + msg[1]
        return s

    def __init__(self, port=9043):
        self.PORT = port
        self.soc = self.buildSocket()
        self.key = RSA.generate(1024, os.urandom)
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

    def deal_with_client(self, connstream):
        data = connstream.recv(4096)

        request = json.loads(data)
        if request['Request'] == 'Certificate':

            userdata = request['Data']
            user_identity = userdata['Identity']
            user_public_key = userdata['KeyUser']

            print "User " + str(user_identity) +\
                  " Requested new Payword Certificate"

            publickey = self.key.publickey()
            payword_json = {"Broker": str(self.identity),
                            "User": str(user_identity),
                            "UserIP": str(self.addr),
                            "KeyBroker": str(publickey.exportKey()),
                            "KeyUser": str(user_public_key),
                            "ExpirationDate": str(datetime.now()),
                            "Info": ''}
            cert_sig = generateSignature(
                payword_json, self.key)
            connstream.send(json.dumps(
                {'Response': 'OK',
                 'Data': payword_json,
                 'Signature': cert_sig}).encode('utf-8'))

        elif request['Request'] == 'Redeem':
            data = request['Data']
            commit = data['Commit']
            commit_sig = data['CommitSignature']
            vendor = commit['Vendor']
            cert = commit['Certificate']
            cert_sig = commit['CertificateSignature']

            print "Vendor " + str(commit['Vendor']) +\
                  " Requested Payword Redeem"

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
            elif not verifySignature(commit, cert['KeyUser'], commit_sig):
                connstream.send(
                    json.dumps({'Response': 'Error',
                                'Data': 'Invalid Commit Signature',
                                'Signature': ''}).encode('utf-8'))
            elif not verifySignature(cert, cert['KeyBroker'], cert_sig):
                connstream.send(
                    json.dumps({'Response': 'Error',
                                'Data': 'Invalid Certificate Signature',
                                'Signature': ''}).encode('utf-8'))
            else:
                if vendor not in self.vendors:
                    self.vendors[vendor] = list()
                if commit['HashRoot'] in self.vendors[vendor]:
                    connstream.send(
                        json.dumps({'Response': 'Error',
                                    'Data': 'Already Redeemed',
                                    'Signature': ''}).encode('utf-8'))
                else:
                    if chainHash (data['Hash'], data['Amount']) != commit['HashRoot']:
                        connstream.send(
                            json.dumps({'Response': 'Error',
                                        'Data': 'Invalid Hash',
                                        'Signature': ''}).encode('utf-8'))
                    else:
                        payed = data['Amount'] * commit['Info'][1]
                        print ('Payed vendor ' + str(vendor) + ': ' + str(payed))
                        self.vendors[vendor].append(commit['HashRoot'])
                        connstream.send(
                            json.dumps({'Response': 'OK',
                                        'Data': 'Redeem Successful: ' + str(payed),
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
                            args=(self.connstream,))
            thread.start()

    def runcmd(self):
        pass


if __name__ == "__main__":

    identity = 7000
    try:
        identity = int(sys.argv[1])
    except ValueError:
        print ('Invalid argument')
        sys.exit(-1)
    except IndexError:
        pass

    broker = Broker(identity)
    broker.serve()
