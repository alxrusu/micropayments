'''This script will serve as a customer client in the micropayments scheme'''
import Crypto.PublicKey.RSA as RSA
import json
import os
import sys
import time

import utils

FRAUD_CERTIFICATE = 1
FRAUD_COMMIT = 2
FRAUD_HASH = 4

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
        self.chainLen = 100
        self.linkValue = 1

    def requestCertificate(self):

        print 'Request new certificate'
        data = {'Identity': self.identity,
                'KeyUser': self.publicKey.exportKey(),
                'Length': self.chainLen,
                'Value': self.linkValue}

        response = utils.getSSLResponse(self.broker, 'Certificate', data, '')
        if response['Response'] == 'OK':

            certificate = response['Data']
            self.certificateSignature = response['Signature']

            if utils.verifySignature(certificate,
                                     certificate['KeyBroker'],
                                     self.certificateSignature):
                self.certificate = certificate
                print 'Certificate signature valid'
                print 'New certificate granted'
            else:
                raise CertificateError('Altered Certificate')
        else:
            raise CertificateError(
                'Certificate Request Refused: ' + str(response['Data']))

    def payVendor(self, vendor, amount, fraud):

        while amount > 0:

            if vendor not in self.knownVendors:

                newCommit = CommittedVendor (vendor, self.chainLen, self.linkValue)

                certificate = self.certificate
                if fraud & FRAUD_CERTIFICATE:
                    print 'Forging certificate'
                    certificate = dict(self.certificate)
                    certificate['Broker'] = "NotScamAtAll"

                data = newCommit.generateCommit(
                    certificate, self.certificateSignature)

                signature = utils.generateSignature(data, self.privateKey)

                if fraud & FRAUD_COMMIT:
                    print 'Forging commit'
                    data['Date'] = 'ieri'

                print 'Sending commit'
                response = utils.getResponse(
                        vendor, 'Commit', data, signature)

                if response['Response'] != 'OK':
                    raise VendorError('Commit Refused: ' + response['Data'])
                else:
                    pass
                self.knownVendors[vendor] = newCommit

            try:
                linkFraud = 0
                if fraud & FRAUD_HASH:
                    print 'Forging hash'
                    linkFraud = 1
                print 'Sending payment'
                amount -= self.knownVendors[
                    vendor].sendPayment(self.identity, amount, linkFraud)
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

            elif cmd[0] == 'clear':

                try:
                    vendor = int(cmd[1])
                except:
                    print ('Invalid Command')
                    continue

                if vendor in self.knownVendors:
                    del self.knownVendors[vendor]

            elif cmd[0] == 'setlen':
                try:
                    length = int(cmd[1])
                    assert length > 1
                    self.chainLen = length
                except:
                    print ('Invalid Command')

            elif cmd[0] == 'setvalue':
                try:
                    value = int(cmd[1])
                    assert value > 0
                    self.linkValue = value
                except:
                    print ('Invalid Command')


            elif cmd[0] == 'exit':
                break

            else:
                print ("Unknown Command")


class CommittedVendor:

    def __init__(self, vendor, chainLen, linkValue):

        self.vendor = vendor
        data = os.urandom(256)
        self.hashChain = list()

        for i in range(chainLen):
            data = utils.chainHash(data, 1)
            self.hashChain.append(data)

        self.lastUsed = chainLen - 1
        self.chainLen = chainLen
        self.linkValue = linkValue

    def generateCommit(self, certificate, signature):
        return {'Vendor': self.vendor,
                'Certificate': certificate,
                'CertificateSignature': signature,
                'HashRoot': self.hashChain[self.chainLen - 1],
                'Date': time.time(),
                'Info': (self.chainLen, self.linkValue)}

    def sendPayment(self, identity, amount, fraud):

        amount = (amount - 1) // self.linkValue + 1
        amount = min(amount, self.lastUsed)
        data = {'Identity': str(identity),
                'Link': self.hashChain[self.lastUsed - amount + fraud],
                'Amount': amount}

        response = utils.getResponse(self.vendor, 'Pay', data, '')
        if response['Response'] == 'OK':
            self.lastUsed -= amount
            print ('Payment successful. Payed ' +
                   str(amount) + ' (x' + str(self.linkValue) +
                   '), Remaining ' + str(self.lastUsed))
            return amount * self.linkValue
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
    broker = 7000
    try:
        identity = int(sys.argv[1])
        broker = int(sys.argv[2])
    except ValueError:
        print ('Invalid argument')
        sys.exit(-1)
    except IndexError:
        pass
    customer = Customer(identity, broker)
    print 'Customer Alive'
    customer.runcmd()
