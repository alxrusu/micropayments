'''This script will serve as a vendor server in the micropayments scheme'''
import socket
import sys
import utils
from threading import Thread
import json


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

    def deal_with_client(self, connstream, port):

        data = connstream.recv(4096)
        request = json.loads(data).decode('utf-8')
        print data

        if request['Request'] == "Commit":
            print "Commit registered"

            try:
                commit = CommittedConsumer (self.PORT, request['Data'], request['Signature'])
            except AssertionError:
                connstream.send(json.dumps({'Response': 'Error', 'Data': 'Invalid Commit', 'Signature': ''}).encode('utf-8'))
            else:
                self.knownCustomers[port].insert (0, commit)
                connstream.send(json.dumps({'Response': 'OK', 'Data': 'Accepted', 'Signature':''}).encode('utf-8'))

        if request['Request'] == "Pay":
            print "Payment registered"

            try:
                commit = self.knownCustomers[port]
                commit.isValid()
            except AssertionError:
                connstream.send(
                    json.dumps({'Response': 'Error', 'Data': 'Commit Expired', 'Signature': ''}).encode('utf-8'))
            except KeyError:
                connstream.send(
                    json.dumps({'Response': 'Error', 'Data': 'Commit Missing', 'Signature': ''}).encode('utf-8'))
            else:
                connstream.send(json.dumps({'Response': 'OK', 'Data': 'Payment Completed', 'Signature':''}).encode('utf-8'))

        connstream.close()

    def serve(self):
        while True:
            conn, addr = self.soc.accept()
            thread = Thread(target=self.deal_with_client,
                            args=(conn, addr))
            thread.start()

    def runcmd(self):

        while True:

            cmd = raw_input()
            cmd = cmd.split(' ')

            if cmd[0] == 'redeem':
                print "now i'm redeeming"

            if cmd[0] == 'exit':
                print "Okay, bye!"
                sys.exit()


class CommittedConsumer:

    def __init__(self, vendor, commit, signature):

        self.commit = commit
        self.hashRoot = commit['HashRoot']

        assert self.commit['Vendor'] == vendor
        assert utils.verifySignature(self.commit, self.commit[
            'Certificate']['KeyUser'], signature)
        assert utils.verifySignature(
            self.commit['Certificate'],
            self.commit['Certificate']['KeyBroker'],
            self.commit['Certificate']['CertificateSignature'])

    def isValid(self, signature):
        assert self.commit['Date'] < self.commit[
            'Certificate']['ExpirationDate']

    def getPayment(self, link, amount):
        pass


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
    vendor.runcmd()
