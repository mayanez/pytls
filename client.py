import os, sys, socket, select, binascii, signal, threading, ushlex, cmd, datetime, ssl
import requests
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

def mode_n(data):
        return data

class Client(cmd.Cmd):
    host = None
    port = None
    session = requests.Session()
    session.mount('https://', SSLAdapter(ssl.PROTOCOL_TLSv1))
    prompt = '>'
    modes = {
                'N': mode_n,

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

        response = self.session.get("https://%s:%s/%s" % (self.host, self.port, file_name), verify='server.pem', cert='client.pem')
        f = open(file_name + str(datetime.datetime.now()), 'wb')
        h = open(file_name + '.sha256', 'wb')

        for chunk in response.iter_content(4096):
            f.write(chunk)

        #re-read file and possibel decrypt

        h.write(response.headers['SHA256'])
        f.close()
        h.close()
        print "%s received" % file_name

    def do_put(self, line):
        args = ushlex.split(line)
        file_name = args[0]
        mode = args[1]

        response = self.session.post("https://%s:%s/%s" % (self.host, self.port, file_name), files={file_name : open(file_name, 'rb')}, verify=False)
        print response.text

    def set_host(self, host):
        self.host = host
    def set_port(self, port):
        self.port = port




if __name__ == '__main__':

    if len(sys.argv) < 3:
        print 'Usage: python client.py HOST PORT'
        sys.exit(1)

    requests.packages.urllib3.disable_warnings()
    signal.signal(signal.SIGINT, signal_handler)
    #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect to remote host
    #try :
        #s.settimeout(2)
        #s.connect((sys.argv[1], int(sys.argv[2])))
    #except :
    #    print 'Unable to connect'
    #    sys.exit()

    client = Client()
    client.set_host(sys.argv[1])
    client.set_port(int(sys.argv[2]))
    client.cmdloop()

    s.close()
    sys.exit()
