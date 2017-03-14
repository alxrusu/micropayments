'''This script will serve as a vendor server in the micropayments scheme'''
import socket
import sys
import utils

class Vendor:

    def __init__ (self, port):
        self.PORT = port
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pass

    def serve(self):
        pass

    def runcmd(self):

        while True:

            cmd = input()
            cmd = cmd.split (' ')

            if cmd[0] == 'redeem':
                pass

            if cmd[0] == 'exit':
                break


class CommittedConsumer:

    def __init__ (self, commit):
        self.commit = commit
        self.hashRoot = commit['HashRoot']

    def isValid (self, vendor, signature):
        assert self.commit['Vendor'] == vendor
        assert self.commit['Date'] < self.commit['Certificate']['ExpirationDate']
        assert utils.verifySignature (self.commit, self.commit['Certificate']['KeyUser'], signature)
        assert utils.verifySignature (self.commit['Certificate'], self.commit['Certificate']['KeyBroker'], self.commit['Certificate']['CertificateSignature'])

    def getPayment (self, link, amount):
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
    vendor = Vendor (identity)
    vendor.runcmd()
