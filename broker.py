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

    def serve(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.load_cert_chain(certfile="cert.pem")

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

        while 1:
            conn, addr = s.accept()
            sslsoc = context.wrap_socket(s, server_side=True)
            print 'Connected with ' + addr[0] + ':' + str(addr[1])
            request = sslsoc.read()
            print request

        s.close()
        pass

    def runcmd(self):
        pass


if __name__ == "__main__":
    broker = Broker()
    broker.serve()
