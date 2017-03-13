'''This script will serve as a broker server in the micropayments scheme'''
import sys
import socket
import ssl


class Broker:

    HOST = ''   # Symbolic name, meaning all available interfaces
    PORT = 0    # Arbitrary non-privileged port
    ssl_certfile = "cert.pem"
    ssl_keyfile = "key.pem"

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
        pass

    def deal_with_client(self, connstream):
        data = connstream.read()

        while data:
            break
            data = connstream.read()

    def serve(self):
        '''
        Server thread
        '''
        err = 0
        msg = None
        try:
            self.soc.bind((self.HOST, self.PORT))
            print "Bind worked\n"
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
        if not err:
            self.conn, self.addr = self.soc.accept()
            print "Accepted client connection to address "\
                + str(self.addr) + "\n"
            try:
                self.connstream = ssl.wrap_socket(
                    self.conn,
                    server_side=True,
                    certfile=self.ssl_certfile,
                    keyfile=self.ssl_keyfile,
                    ssl_version=ssl.PROTOCOL_TLSv1
                )
                print "SSL wrap succeeded for sever"
            except socket.error, msg:
                if (msg is not None):
                    print "SSL wrap failed for server: " +\
                        str(msg[0]) + " Message " + msg[1]
                err = 1

            while True:
                data = self.connstream.recv(1024)
                if data:
                    print "server: " + data
                else:
                    break
        self.soc.close()
        self.connstream.close()
        print "exit server"

    def runcmd(self):
        pass


if __name__ == "__main__":
    broker = Broker()
    broker.serve()
