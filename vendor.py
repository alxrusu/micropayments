'''This script will serve as a vendor server in the micropayments scheme'''
import socket
import ssl

# SET VARIABLES


class Vendor:
    packet, reply = "<packet>SOME_DATA</packet>", ""
    HOST = 'localhost'
    PORT = 0
    ssl_certfile = "cert.pem"

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

    def ssl_connect(self):
        err = 0
        try:
            self.ssl_sock = ssl.wrap_socket(
                self.soc,
                ca_certs=self.ssl_certfile,
                cert_reqs=ssl.CERT_REQUIRED)
            # print "Wrapped client socket for SSL"
        except socket.error:
            # print "SSL socket wrapping failed"
            err = 1

        if not err:
            try:
                self.ssl_sock.connect((self.HOST, self.PORT))
                # print "client socket connected\n"
            except:  # socket.error, msg:
                # print("Socket connection error in client: ", msg)
                err = 1

        if err:
            return False
        return True

    def ssl_disconnect(self):
        self.soc.close()
        self.ssl_sock.close()
        print "exit client"

    def contact(self):
        '''
        Client thread
        '''
        if not self.ssl_connect():
            return

        self.ssl_sock.sendall("Twas brillig and the slithy toves")
        self.ssl_disconnect()

    def serve(self):
        pass

    def runcmd(self):
        pass


if __name__ == "__main__":
    vendor = Vendor()
    vendor.contact()
