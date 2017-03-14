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
        networking = Thread(target=self.serve)
        networking.start()

    def deal_with_client(self, connstream):
        data = connstream.recv(4096)

        print data
        request = json.loads(data)
        if request['Request'] == "Commit":
            print "got a payment!"
            connstream.send(json.dumps({'Response': 'OK', 'Data': 'Accepted'}))
        if request['Request'] == "Pay":
            print "got Money!"
            connstream.send(json.dumps({'Response': 'OK', 'Data': 'Accepted'}))
        connstream.close()

    def serve(self):
        while True:
            self.conn, self.addr = self.soc.accept()
            thread = Thread(target=self.deal_with_client,
                            args=(self.conn,))
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

    def __init__(self, commit):
        self.commit = commit
        self.hashRoot = commit['HashRoot']

    def isValid(self, vendor, signature):
        assert self.commit['Vendor'] == vendor
        assert self.commit['Date'] < self.commit[
            'Certificate']['ExpirationDate']
        assert utils.verifySignature(self.commit, self.commit[
                                     'Certificate']['KeyUser'], signature)
        assert utils.verifySignature(
            self.commit['Certificate'],
            self.commit['Certificate']['KeyBroker'],
            self.commit['Certificate']['CertificateSignature'])

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
