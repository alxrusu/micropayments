'''This script will serve as a customer client in the micropayments scheme'''
import ssl
import Crypto.PublicKey.RSA as RSA
import socket
import json
import os
import sys
import time

import utils

if sys.version_info[0] < 3:
    input = raw_input


class Customer:

    def __init__(self, identity, broker):

        self.privateKey = RSA.generate(1024, os.urandom)
        self.publicKey = self.privateKey.publickey()
        self.identity = identity
        self.broker = broker
        self.certificate = None
        self.certificateSignature = None
        self.knownVendors = dict()

    def requestCertificate(self):

        brokerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        brokerSocket_ssl = ssl.wrap_socket(
            brokerSocket,
            ca_certs=utils.ssl_certfile,
            cert_reqs=ssl.CERT_REQUIRED)
        brokerSocket_ssl.connect(('localhost', self.broker))

        data = {'Identity': self.identity,
                'KeyUser': self.publicKey.exportKey()}
        brokerSocket_ssl.send(json.dumps(
            {'Request': 'Certificate',
             'Data': data,
             'Signature': ''}).encode('utf-8'))

        response = json.loads(brokerSocket_ssl.read(4096).decode('utf-8'))
        if response['Response'] == 'OK':

            certificate = response['Data']
            self.certificateSignature = response['Signature']

            print "\n\n" + json.dumps(certificate) + "\n\n"
            if utils.verifySignature(certificate,
                                     certificate['KeyBroker'],
                                     self.certificateSignature):
                self.certificate = certificate
            else:
                raise CertificateError('Altered Certificate')
        else:
            raise CertificateError(
                'Certificate Request Refused: ' + str(response['Data']))

    def payVendor(self, vendor, amount):

        while amount > 0:

            if vendor not in self.knownVendors:

                newCommit = CommittedVendor(vendor)
                data = newCommit.generateCommit(
                    self.certificate, self.certificateSignature)
                signature = utils.generateSignature(data, self.privateKey)

                response = utils.getResponse(vendor, 'Commit', data, signature)
                if response['Response'] != 'OK':
                    raise VendorError('Commit Refused: ' + response['Data'])
                else:
                    print response['Data']
                self.knownVendors[vendor] = newCommit

            try:
                amount -= self.knownVendors[vendor].sendPayment(amount)
            except PaymentError, e:
                raise e

            if self.knownVendors[vendor].lastUsed == 0:
                del self.knownVendors[vendor]

    def runcmd(self):

        while True:

            cmd = input()
            cmd = cmd.split(' ')

            if cmd[0] == 'pay':

                try:
                    vendor = int(cmd[1])
                    amount = int(cmd[2])
                except:
                    print ('Invalid Command')
                    continue

                if self.certificate is None or\
                        time.time() > self.certificate['ExpirationDate']:
                    try:
                        self.requestCertificate()
                    except CertificateError, e:
                        print (e.arg)
                        sys.exit(-1)

                try:
                    self.payVendor(vendor, amount)
                except (PaymentError, VendorError) as e:
                    print (e.arg)

            if cmd[0] == 'exit':
                break


class CommittedVendor:

    def __init__(self, vendor, chainLen=100):

        self.vendor = vendor
        data = os.urandom(256)
        self.hashChain = list()

        for i in range(chainLen):
            data = utils.chainHash(data, 1)
            self.hashChain.append(data)

        self.lastUsed = chainLen
        self.chainLen = chainLen

    def generateCommit(self, certificate, signature):
        return {'Vendor': self.vendor,
                'Certificate': certificate,
                'CertificateSignature': signature,
                'HashRoot': self.hashChain[self.chainLen - 1],
                'Date': time.time(),
                'Info': self.chainLen}

    def sendPayment(self, amount):

        amount = min(amount, self.lastUsed)
        data = {'Link': self.hashChain[
            self.lastUsed - amount], 'Amount': amount}

        response = utils.getResponse(self.vendor, 'Pay', data, '')
        if response['Response'] == 'OK':
            self.lastUsed -= amount
            print ('Payment successful. Payed' +
                   str(amount) + ', Remaining ' +
                   str(self.lastUsed))
            return amount
        else:
            raise PaymentError('Payment Refused: ' + response['Data'])


class PaymentError (RuntimeError):
    def __init__(self, arg):
        self.arg = arg


class VendorError (RuntimeError):
    def __init__(self, arg):
        self.arg = arg


class CertificateError (RuntimeError):
    def __init__(self, arg):
        self.arg = arg


if __name__ == '__main__':

    identity = 9000
    broker = 9043
    try:
        identity = int(sys.argv[1])
        broker = int(sys.argv[2])
    except ValueError:
        print ('Invalid argument')
        sys.exit(-1)
    except IndexError:
        pass
    customer = Customer(identity, broker)
    customer.runcmd()
