import os, sys, socket, select, binascii, signal, threading, ushlex, cmd, datetime, ssl
import requests, hashlib
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

class SSLAdapter(HTTPAdapter):
    '''An HTTPS Transport Adapter that uses an arbitrary SSL version.'''
    def __init__(self, ssl_version=None, **kwargs):
        self.ssl_version = ssl_version

        super(SSLAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=self.ssl_version)

def signal_handler(signal, frame):
    print "Exiting..."
    os._exit(1)

def gen_hash(data):
    m = hashlib.sha256()
    m.update(data)
    return m.hexdigest()

def mode_n(data):
        return data

class Client(cmd.Cmd):
    host = None
    port = None
    server_cert = None
    cert = None
    session = requests.Session()
    session.mount('https://', SSLAdapter(ssl.PROTOCOL_TLSv1))
    prompt = '>'
    modes = {
                'N': mode_n
            }

    def do_EOF(self, line):
        return True

    def do_stop(self, line):
        signal_handler(None, None)
        return

    def do_get(self, line):
        args = ushlex.split(line)
        file_name = args[0]
        mode = args[1]

        #add error checking if cant reach host
        response = self.session.get("https://%s:%s/%s" % (self.host, self.port, file_name), verify=self.server_cert, cert=self.cert)
        f = open(file_name + str(datetime.datetime.now()), 'wb')

        for chunk in response.iter_content(4096):
            f.write(chunk)

        #re-read file and possibel decrypt

        #verify hash
        data_hash = response.headers['SHA256']
        f.close()

        print "%s received" % file_name

    def do_put(self, line):
        args = ushlex.split(line)
        file_name = args[0]
        mode = args[1]

        f = open(file_name, 'rb')
        data = f.read()
        params ={'hash' : gen_hash(data)}
        f.close()
        
        #add error checking if cant reach host
        response = self.session.post("https://%s:%s/%s" % (self.host, self.port, file_name), params=params, files={file_name : open(file_name, 'rb')}, verify=self.server_cert, cert=self.cert)
        print response.text



if __name__ == '__main__':

    if len(sys.argv) < 5:
        print 'Usage: python client.py HOST PORT SERVER_CERT CLIENT_CERT'
        sys.exit(1)

    requests.packages.urllib3.disable_warnings()
    signal.signal(signal.SIGINT, signal_handler)

    client = Client()

    client.host = sys.argv[1] # verify IP Address
    client.port = int(sys.argv[2])
    client.server_cert = sys.argv[3]
    client.cert = sys.argv[4]

    client.cmdloop()

    s.close()
    sys.exit()
