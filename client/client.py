import os, sys, socket, select, binascii, signal, threading, cmd, datetime, ssl
import requests, hashlib, random
from Crypto.Cipher import AES
from Crypto import Random
"""
Python TLS Client. 4180 - Homework 2
Miguel A. Yanez - may2114

"""

try:
    import ushlex
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.poolmanager import PoolManager
except ImportError:
    print 'Please run the root Makefile to install dependencies.'
    sys.exit(1)

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
    """Generates a SHA256 hash"""
    m = hashlib.sha256()
    m.update(data)
    return m.hexdigest()

def mode_n(data):
    """Mode N: Does not encrypt. Sends as plaintext"""
    return data

def mode_e(data, password, encrypt):
    """Mode E: Encrypts/Decrypts using AES."""
    aes_cipher = AESCipher(password)

    if (encrypt):
        return aes_cipher.encrypt(data)
    else:
        return aes_cipher.decrypt(data)

class AESCipher(object):
    """AES Cipher class using PKCS5 padding"""

    def __init__(self, password):
        self.password = password

    def encrypt(self, plain):
        '''Encrypts using constant IV '''
        random.seed(self.password)
        plain = self.pkcs5_pad(plain)
        key = random.getrandbits(128)
        cipher = AES.new("%x" % key, AES.MODE_CBC, '0000000000000000')
        return cipher.encrypt(plain)

    def decrypt(self, enc):
        '''Decrypts using constant IV'''
        random.seed(self.password)
        cipher = AES.new("%x" % random.getrandbits(128), AES.MODE_CBC, '0000000000000000')
        return self.pkcs5_unpad(cipher.decrypt(enc))

    @staticmethod
    def pkcs5_pad(s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def pkcs5_unpad(s):
        return s[0:-ord(s[-1])]

class Client(cmd.Cmd):
    """TLS Client with HTTP Protocol backend"""
    host = None
    port = None
    ca_cert = None
    cert = None
    key = None
    session = requests.Session()
    session.mount('https://', SSLAdapter(ssl.PROTOCOL_TLSv1))
    prompt = '>'

    #handle invalid modes
    modes = {
                'N': mode_n,
                'E': mode_e
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
        '''Prints Help message for GET command'''
        print '\n'.join(['get file mode [password]',
                         '\tmode -- N, E',
                         '\t[password] -- only for E mode'])

    def do_get(self, line):
        '''Retrieves a file from a server'''
        args = ushlex.split(line)

        if len(args) < 2:
            self.help_get()
            return

        file_name = args[0]
        mode = args[1]

        if mode not in self.modes:
            print '*** Invalid mode, options are "N" "E"'
            return

        try:
            response = self.session.get("https://%s:%s/%s" % (self.host, self.port, file_name), verify=self.ca_cert, cert=(self.cert, self.key))
        except:
            print '*** There was an error in the connection. Please try again.'
            return

        if response.status_code == 404:
            print '*** Error for %s' % file_name
            print response.text
            return

        f = open(file_name, 'wb')
        for chunk in response.iter_content(4096):
            f.write(chunk)
        f.close()

        f = open(file_name, 'rb')
        data = f.read()

        if (mode == 'E'):
            if len(args) < 3:
                self.help_get()
                return

            password = args[2]

            if len(password) != 8:
                print '*** Password must be of length 8'
                f.close()
                return

            fd = open(file_name + '.dec', 'wb')
            plain = self.modes[mode](data, password, False)
            fd.write(plain)
            data = plain
            fd.close()

        computed_hash = gen_hash(data)
        f.close()

        data_hash = response.headers['SHA256']

        if data_hash == computed_hash:
            print "%s received" % file_name

            if (mode == 'E'):
                os.remove(file_name)
                os.rename(file_name + '.dec', file_name)
        else:
            os.remove(file_name)

            if (mode == 'E'):
                os.remove(file_name + '.dec')
                print "*** Decryption of %s failed." % file_name
            else:
                print "*** %s did not pass verification" % file_name

    def help_put(self):
        '''Prints help message for PUT command'''
        print '\n'.join(['put file mode [password]',
                         '\tmode -- N, E',
                         '\t[password] -- only for E mode'])

    def do_put(self, line):
        '''Puts a file on the server'''
        args = ushlex.split(line)
        file_name = args[0]
        up_file = file_name
        mode = args[1]
        password = None

        f = open(file_name, 'rb')
        data = f.read()
        params ={'hash' : gen_hash(data)}
        f.close()

        if mode == 'E':
            if len(args) < 3:
                self.help_put()
                return
            password = args[2]

            if len(password) != 8:
                print '*** Password must be of length 8'
                return

            up_file = file_name + '.enc'
            fe = open(up_file, 'wb')
            fe.write(self.modes[mode](data, password, True))
            fe.close()

        response = None

        try:
            response = self.session.post("https://%s:%s/%s" % (self.host, self.port, file_name), params=params, files={file_name : open(up_file, 'rb')}, verify=self.ca_cert, cert=(self.cert, self.key))
        except requests.exceptions.SSLError:
           print '*** Invalid SSL Certificate. Please verify certificate.'
           if mode == 'E':
               os.remove(up_file)
           return
        except:
           print '*** There was an error in the connection. Please try again.'
           if mode == 'E':
               os.remove(up_file)
           return

        if mode == 'E':
            os.remove(up_file)

        print response.text



if __name__ == '__main__':

    if len(sys.argv) < 6:
        print 'Usage: python client.py HOST PORT CA_CERT CLIENT_CERT CLIENT_KEY'
        sys.exit(1)

    requests.packages.urllib3.disable_warnings()
    signal.signal(signal.SIGINT, signal_handler)

    client = Client()

    try:
        valid = socket.inet_aton(sys.argv[1])

        if (valid > 0):
            client.host = sys.argv[1]
    except:
        print 'Invalid HOST IP'
        sys.exit(1)

    try:
        client.port = int(sys.argv[2])
    except ValueError:
        print 'Invalid PORT'
        sys.exit(1)

    client.ca_cert = sys.argv[3]
    client.cert = sys.argv[4]
    client.key = sys.argv[5]

    if (not(os.path.isfile(client.ca_cert) and os.path.isfile(client.cert) and os.path.isfile(client.key))):
        print 'Files for CA_CERT, CLIENT_CERT, CLIENT_KEY may be invalid.'
        sys.exit(1)

    client.cmdloop()

    sys.exit()
