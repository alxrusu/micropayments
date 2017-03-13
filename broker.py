'''This script will serve as a broker server in the micropayments scheme'''
import sys
import socket


class Broker:

    HOST = ''   # Symbolic name, meaning all available interfaces
    PORT = 0    # Arbitrary non-privileged port

    def __init__(self, port=9043):
        self.PORT = port
        pass

    def serve(self):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print 'Socket created'

        # Bind socket to local host and port
        try:
            s.bind((self.HOST, self.PORT))
        except socket.error as msg:
            print 'Bind failed. Error Code : ' \
                + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

        print 'Socket bind complete'

        # Start listening on socket
        s.listen(10)
        print 'Socket now listening'

        # now keep talking with the client
        while 1:
            # wait to accept a connection - blocking call
            conn, addr = s.accept()
            print 'Connected with ' + addr[0] + ':' + str(addr[1])

        s.close()
        pass

    def runcmd(self):
        pass
