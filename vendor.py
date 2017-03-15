'''This script will serve as a vendor server in the micropayments scheme'''
import socket
import sys
import utils
from threading import Thread
import json
import time

FRAUD_COMMIT = 1
FRAUD_HASH = 2
FRAUD_AMOUNT = 4

class Vendor:

    HOST = ''

    def __init__(self, port):
        self.PORT = port
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.bind((self.HOST, self.PORT))
        self.soc.listen(10)
        self.knownCustomers = dict()
        networking = Thread(target=self.serve)
        networking.start()

    def deal_with_client(self, connstream):

        data = connstream.recv(4096)
        request = json.loads(data.decode('utf-8'))

        if request['Request'] == "Commit":
            print "Commit registered\n"

            identity = request['Data']['Certificate']['User']
            try:
                commit = CommittedConsumer(
                    self.PORT, request['Data'], request['Signature'])
            except AssertionError:
                connstream.send(json.dumps({'Response': 'Error',
                                            'Data': 'Invalid Commit',
                                            'Signature': ''}).encode('utf-8'))
            else:
                if identity not in self.knownCustomers:
                    self.knownCustomers[identity] = list()
                self.knownCustomers[identity].insert(0, commit)
                connstream.send(
                    json.dumps({'Response': 'OK',
                                'Data': 'Accepted',
                                'Signature': ''}).encode('utf-8'))

        if request['Request'] == "Pay":
            print "Payment registered"

            identity = request['Data']['Identity']
            try:
                commit = self.knownCustomers[identity]
                commit = commit[0]

                commit.isValid()
                commit.getPayment(request['Data']['Link'], request[
                                  'Data']['Amount'])
            except AssertionError:
                connstream.send(
                    json.dumps({'Response': 'Error',
                                'Data': 'Commit Expired',
                                'Signature': ''}).encode('utf-8'))
            except KeyError:
                connstream.send(
                    json.dumps({'Response': 'Error',
                                'Data': 'Commit Missing',
                                'Signature': ''}).encode('utf-8'))
            except PaymentError as e:
                connstream.send(
                    json.dumps({'Response': 'Error',
                                'Data': 'Invalid Payment ' + e.arg,
                                'Signature': ''}).encode('utf-8'))
            else:
                connstream.send(json.dumps(
                    {'Response': 'OK',
                     'Data': 'Payment Completed',
                     'Signature': ''}).encode('utf-8'))

        connstream.close()

    def serve(self):
        while True:
            conn, addr = self.soc.accept()
            thread = Thread(target=self.deal_with_client,
                            args=(conn, ))
            thread.start()

    def runcmd(self):

        while True:

            cmd = raw_input()
            cmd = cmd.split(' ')

            if cmd[0] == 'redeem' or cmd[0] == 'fraud':

                fraud = 0
                try:
                    consumer = int(cmd[1])
                    consumer = str(consumer)
                    if cmd[0] == 'fraud':
                        fraud = int(cmd[2])
                    commitList = self.knownCustomers[consumer]
                except KeyError:
                    print ('No payments for user ' + consumer)
                    continue
                except:
                    print ('Invalid Command')
                    continue

                for customerCommit in commitList:

                    commit = customerCommit.commit
                    hash = customerCommit.lastLink
                    amount = customerCommit.amount
                    signature = customerCommit.signature

                    if fraud & FRAUD_COMMIT:
                        print 'Forging commit'
                        commit = dict(commit)
                        commit['Data'] = 'Legit'

                    if fraud & FRAUD_HASH:
                        print 'Forging hash'
                        hash = utils.chainHash(hash, 1)

                    if fraud & FRAUD_AMOUNT:
                        print 'Forging amount'
                        amount += 1

                    data = {'Commit': commit,
                            'CommitSignature': signature,
                            'Hash': hash,
                            'Amount': amount}
                    response = utils.getSSLResponse(
                        int(customerCommit.commit['Certificate']['Broker']),
                        'Redeem', data, '')
                    print ('Trying to redeem ' + str(customerCommit.amount))
                    if response['Response'] == 'OK':
                        print (response['Data'])
                    else:
                        print ('Redeem failed ' + json.dumps(response['Data']))

            elif cmd[0] == 'clear':

                try:
                    consumer = int(cmd[1])
                    consumer = str(consumer)
                except:
                    print ('Invalid Command')
                    continue

                if consumer in self.knownCustomers:
                    del self.knownCustomers[consumer]

            elif cmd[0] == 'exit':
                print "Okay, bye!"
                sys.exit()

            else:
                print ("Unknown Command")


class CommittedConsumer:

    def __init__(self, vendor, commit, signature):

        self.commit = commit
        self.signature = signature
        self.lastLink = commit['HashRoot']
        self.amount = 0
        self.value = commit['Info'][1]

        assert self.commit['Vendor'] == vendor
        print 'Vendor valid'
        assert utils.verifySignature(self.commit, self.commit[
            'Certificate']['KeyUser'], signature)
        print 'Commit signature valid'
        assert utils.verifySignature(
            self.commit['Certificate'],
            self.commit['Certificate']['KeyBroker'],
            self.commit['CertificateSignature'])
        print 'Certificate signature valid'

    def isValid(self):
        assert self.commit['Date'] < time.time()
        print 'Commit date valid\n'

    def getPayment(self, link, amount):
        if utils.chainHash(link, amount) != self.lastLink:
            raise PaymentError('Invalid Hash')
        self.lastLink = link
        self.amount += amount
        print ('Got a payment of ' + str(amount) +
               ' (x' + str(self.value) + ')')


class PaymentError (RuntimeError):
    def __init__(self, arg):
        self.arg = arg


if __name__ == "__main__":
    identity = 9000
    try:
        identity = int(sys.argv[1])
    except ValueError:
        print ('Invalid argument')
        sys.exit(-1)
    except IndexError:
        pass
    vendor = Vendor(identity)
    print 'Vendor listening'
    vendor.runcmd()
