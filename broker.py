'''This script will serve as a broker server in the micropayments scheme'''
import sys
import socket
import ssl


class Broker:

    HOST = ''   # Symbolic name, meaning all available interfaces
    PORT = 0    # Arbitrary non-privileged port

    def __init__(self, port=9043):
        self.PORT = port
        pass

    def deal_with_client(self, connstream):
        data = connstream.read()

        while data:
            break
            data = connstream.read()

    def serve(self):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print 'Socket created'

        try:
            s.bind((self.HOST, self.PORT))
        except socket.error as msg:
            print 'Bind failed. Error Code : ' \
                + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

        print 'Socket bind complete'

        s.listen(10)
        print 'Socket now listening'

        while True:
            newsocket, fromaddr = s.accept()
            connstream = context.wrap_socket(newsocket, server_side=True)
            try:
                self.deal_with_client(connstream)
            finally:
                connstream.shutdown(socket.SHUT_RDWR)
                connstream.close()

    def runcmd(self):
        pass


if __name__ == "__main__":
    broker = Broker()
    broker.serve()
