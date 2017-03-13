'''This script will serve as a customer client in the micropayments scheme'''
import ssl
import Crypto.PublicKey.RSA as RSA
import socket
import hashlib
import threading
import json
import os
import sys
import time

serverCert = 'cert.pem'


class Customer:

    def __init__(self, port, broker):
        self.privateKey = RSA.generate(1024, os.urandom)
        self.publicKey = self.privateKey.publickey()
        self.identity = port
        self.broker = broker
        self.certificate = None
        self.certificateSignature = None
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(('', port))
        self.server.listen(5)

    def requestCertificate(self):
        brokerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        brokerSocket_ssl = ssl.wrap_socket(
            brokerSocket, ca_certs=serverCert, cert_reqs=ssl.CERT_REQUIRED)
        brokerSocket_ssl.connect(('localhost', self.broker))
        data = {'Identity': self.identity,
                'KeyUser': self.publicKey.exportKey()}
        brokerSocket_ssl.send(json.dumps(
            {'Request': 'Certificate', 'Data': data}).encode('utf-8'))
        response = json.loads(brokerSocket_ssl.read(4096).decode('utf-8'))
        if response['Response'] == 'OK':
            certificate = response['Data']
            self.certificateSignature = response['Signature']
            key = RSA.importKey(certificate['KeyBroker'])
            sha1 = hashlib.sha1()
            sha1.update(json.dumps(certificate))
            if key.verify(sha1.hexdigest()):
                self.certificate = certificate

    def contact(self):
        pass

    def serve(self):
        while True:
            conn, addr = self.server.accept()
            data = json.loads(conn.recv(4096).decode('utf-8'))
            print ('Connection: ' + addr)
            print ('Data: ' + data)
            if data['Request'] == 'Key':
                conn.send(json.dumps({'Response': 'OK',
                                      'Data': self.publicKey.exportKey(
                                      ), 'Signature': ''}).encode('utf-8'))
            else:
                conn.send(json.dumps(
                    {'Response': 'Error', 'Data':
                     'Unknown Request', 'Signature': ''}).encode('utf-8'))
            conn.close()

    def runcmd(self):
        threading.Thread(target=self.serve).start()
        while True:
            cmd = input()
            cmd = cmd.split(' ')
            if cmd[0] == 'pay':
                try:
                    vendor = int(cmd[1])
                    ammount = int(cmd[2])
                except:
                    print ('Invalid Command')
                    continue
                if self.certificate is None or time.time() >\
                        self.certificate['ExpirationDate']:
                    self.requestCertificate()

            if cmd[0] == 'exit':
                break


class commitedVendor:

    def __init__(self, vendor, certificate, chainLen=100):
        self.vendor = vendor
        seed = os.urandom(256)
        self.hashChain = list()
        for i in range(chainLen):
            sha1 = hashlib.sha1()
            sha1.update(seed)
            seed = sha1.hexdigest()
            self.hashChain[i] = seed
        self.lastUsed = chainLen
        self.chainLen = chainLen


if __name__ == '__main__':
    port = 9043
    broker = 10000
    try:
        port = int(sys.argv[1])
        broker = int(sys.argv[2])
    except ValueError:
        print ('Invalid argument')
        sys.exit(-1)
    except IndexError:
        pass
    customer = Customer(port, broker)
    customer.runcmd()
