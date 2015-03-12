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
    
    #handle invalid modes
    modes = {
                'N': mode_n
            }

    def do_EOF(self, line):
        return True

    def default(self, line):
        print "*** Invalid commands, options are 'get' 'put' 'stop'"

    def do_stop(self, line):
        """Exits the program"""
        signal_handler(None, None)
        return

    def help_get(self):
        print '\n'.join(['get file mode [password]',
                         '\tmode -- N, E',
                         '\t[password] -- only for E mode'])

    def do_get(self, line):
        args = ushlex.split(line)
        file_name = args[0]
        mode = args[1]

        #add error checking if cant reach host
        #handle 404 if file not found
        response = self.session.get("https://%s:%s/%s" % (self.host, self.port, file_name), verify=self.server_cert, cert=self.cert)
        
        # Might there be a way to avoid this?
        f = open(file_name, 'wb')
        for chunk in response.iter_content(4096):
            f.write(chunk)
        f.close()
        
        f = open(file_name, 'rb')
        data = f.read()
        computed_hash = gen_hash(data)
        f.close()

        data_hash = response.headers['SHA256']

        if data_hash == computed_hash:
            print "%s received" % file_name
        else:
            os.remove(file_name)
            print "%s did not pass verification" % file_name

    def help_put(self):
        print '\n'.join(['put file mode [password]',
                         '\tmode -- N, E',
                         '\t[password] -- only for E mode'])

    def do_put(self, line):
        args = ushlex.split(line)
        file_name = args[0]
        mode = args[1]

        #handle if file exists before uploading
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
    
    sys.exit()
