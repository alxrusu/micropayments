import Crypto.PublicKey.RSA as RSA
import socket
import ssl
import hashlib
import json

ssl_certfile = "cert.pem"
ssl_keyfile = "key.pem"


def generateSignature(data, privateKey):
    sha1 = hashlib.sha1()
    sha1.update(json.dumps(data).encode('utf-8'))
    return privateKey.sign(sha1.hexdigest(), '')


def verifySignature(data, publicKey, signature):
    publicKey = RSA.importKey(publicKey)
    sha1 = hashlib.sha1()
    sha1.update(json.dumps(data))
    return publicKey.verify(sha1.hexdigest(), signature)


def chainHash(data, i):
    sha1 = hashlib.sha1()
    for _ in range(i):
        sha1 = hashlib.sha1()
        sha1.update(data)
        data = sha1.hexdigest()
    return sha1.hexdigest()


def getResponse(port, request, data, signature):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', port))
    s.send(json.dumps({'Request': request, 'Data': data,
                       'Signature': signature}).encode('utf-8'))
    raw_response = s.recv(4096).decode('utf-8')
    print "\nResponse\n" + raw_response + "\n\n"
    response = json.loads(raw_response)
    s.close()
    return response


def getSSLResponse(port, request, data, signature):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_ssl = ssl.wrap_socket(
        s,
        ca_certs=ssl_certfile,
        cert_reqs=ssl.CERT_REQUIRED)
    s_ssl.connect(('localhost', port))
    s_ssl.send(json.dumps({'Request': request, 'Data': data,
                           'Signature': signature}).encode('utf-8'))
    raw_response = s_ssl.recv(4096).decode('utf-8')
    print "\n\n" + raw_response + "\n\n"
    response = json.loads(raw_response)
    s_ssl.close()
    return response
