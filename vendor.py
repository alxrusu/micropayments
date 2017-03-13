'''This script will serve as a vendor server in the micropayments scheme'''
import socket
import ssl

# SET VARIABLES


class Vendor:
    packet, reply = "<packet>SOME_DATA</packet>", ""
    HOST = 'localhost'
    PORT = 0

    def __init__(self, port=9043):
        self.PORT = port
        pass

    def contact(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3

        conn = context.wrap_socket(sock, server_hostname=self.HOST)
        conn.connect((self.HOST, self.PORT))
        sock.send(self.packet)
        print sock.recv(1280)

        # CLOSE SOCKET CONNECTION
        sock.close()

        pass

    def serve(self):
        pass

    def runcmd(self):
        pass


if __name__ == "__main__":
    vendor = Vendor()
    vendor.contact()
