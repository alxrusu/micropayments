'''This script will serve as a customer client in the micropayments scheme'''
import ssl
import Crypto.PublicKey.RSA as RSA
import socket
import json
import os
import sys
import time

import utils

CERTIFICATE_FRAUD = 1
LINK_FRAUD = 2
PAYWORD_FRAUD = 4

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
        self.fraud = 0

    def requestCertificate(self):

        data = {'Identity': self.identity,
                'KeyUser': self.publicKey.exportKey()}

        response = utils.getSSLResponse (self.broker, 'Certificate', data, '')
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

    def payVendor(self, vendor, amount, fraud):

        self.fraud = fraud

        while amount > 0:

            if vendor not in self.knownVendors:

                newCommit = CommittedVendor(vendor)
                certificate_copy = dict(self.certificate)
                certificate_copy['Broker'] = "NotScamAtAll"
                if CERTIFICATE_FRAUD & fraud:
                    data = newCommit.generateCommit(
                        certificate_copy, self.certificateSignature)
                else:
                    data = newCommit.generateCommit(
                        self.certificate, self.certificateSignature)
                signature = utils.generateSignature(data, self.privateKey)

                data_copy = dict(data)
                if PAYWORD_FRAUD & fraud:
                    data_copy['Date'] = 'ieri'
                    response = utils.getResponse(
                        vendor, 'Commit', data_copy, signature)
                else:
                    response = utils.getResponse(
                        vendor, 'Commit', data, signature)
                if response['Response'] != 'OK':
                    raise VendorError('Commit Refused: ' + response['Data'])
                else:
                    print response['Data']
                self.knownVendors[vendor] = newCommit

            try:
                if LINK_FRAUD & fraud:
                    amount -= self.knownVendors[
                        vendor].sendLinkFraudPayment(amount)
                else:
                    amount -= self.knownVendors[vendor].sendPayment(self.identity, amount)
            except PaymentError, e:
                raise e

            if self.knownVendors[vendor].lastUsed == 0:
                del self.knownVendors[vendor]

    def runcmd(self):

        while True:

            cmd = input()
            cmd = cmd.split(' ')

            if cmd[0] == 'pay' or cmd[0] == 'fraud':

                fraud = 0
                try:
                    vendor = int(cmd[1])
                    amount = int(cmd[2])
                    if cmd[0] == 'fraud':
                        fraud = int(cmd[3])
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
                    self.payVendor(vendor, amount, fraud)
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

        self.lastUsed = chainLen - 1
        self.chainLen = chainLen

    def genHashChain(self, chainLen=100):
        data = os.urandom(256)
        hashChain = list()

        for i in range(chainLen):
            data = utils.chainHash(data, 1)
            hashChain.append(data)
        return hashChain

    def generateCommit(self, certificate, signature):
        return {'Vendor': self.vendor,
                'Certificate': certificate,
                'CertificateSignature': signature,
                'HashRoot': self.hashChain[self.chainLen - 1],
                'Date': time.time(),
                'Info': self.chainLen}

    def sendPayment(self, identity, amount):

        amount = min(amount, self.lastUsed)
        data = {'Identity': str(identity),
            'Link': self.hashChain[self.lastUsed - amount],
            'Amount': amount}

        response = utils.getResponse(self.vendor, 'Pay', data, '')
        if response['Response'] == 'OK':
            self.lastUsed -= amount
            print ('Payment successful. Payed' +
                   str(amount) + ', Remaining ' +
                   str(self.lastUsed))
            return amount
        else:
            raise PaymentError('Payment Refused: ' + response['Data'])

    def sendLinkFraudPayment(self, amount, fraud):
        amount = min(amount, self.lastUsed)
        data = {'Link': self.genHashChain[
            self.lastUsed - amount], 'Amount': amount}

        response = utils.getResponse(self.vendor, 'Pay', data, '')
        if response['Response'] == 'OK':
            self.lastUsed -= amount
            print ('Payment successful. Payed ' + str(amount) +
                   ', Remaining ' + str(self.lastUsed))
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

    identity = 8000
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
