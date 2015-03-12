import sys, os, socket, ushlex, logging, select, binascii, threading, signal
from OpenSSL import SSL

# logger = logging.getLogger(__name__)

BUFFER_SIZE = 4096

def signal_handler(signal, frame):
    os._exit(1)

def verify_cb(conn, cert, errnum, depth, ok):
    print 'Got certificate: %s' % cert.get_subject()
    return ok

def process_request(sock, data):
    print "Processing"
    tokens = ushlex.split(data)
    
    command = ''
    file_name = ''
    mode = ''
    password = ''

    if len(tokens) < 3:
        raise Exception("Invalid Command Format!")

    if len(tokens) >=3:
        command = tokens[0]
        file_name = tokens[1]
        mode = tokens[2]

    if (mode == 'E' and len(tokens) == 4):
        password = tokens[3]

    print "Parsed: %s %s %s %s" % (command, file_name, mode, password)
    # logger.debug("Parsed: %s %s %s %s" % (command, file_name, mode, password))

    if (command == 'get'):
        #get a file
        f = open(file_name, 'rb')
        buff = f.read()
        print "Sending %s" % file_name

        try:
            sock.sendall(binascii.hexlify(buff))
            f.close()
            sock.sendall('ack')
        except:
            print "exception"
            raise Exception()
        #sock.shutdown(socket.SHUT_WR)

    elif (command == 'put'):
        print "nothing"
    
    print "done process"    
    return


class Server(threading.Thread):

    def __init__(self, port, host='localhost'):
        threading.Thread.__init__(self)
        self.port = port
        self.host = host
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.users = {}

        try:
            self.server.bind((self.host, self.port))
        except socket.error:
            print('Bind failed %s' % (socket.error))
            sys.exit()
 
        self.server.listen(10)

    def run_thread(self, conn, addr):
        print('Client connected with ' + addr[0] + ':' + str(addr[1]))
        while True:
            data = conn.recv(4096)
            try:
                process_request(conn, data)     
            except:
                print "Error Processing Request"        
        conn.close() # Close
        return

    def run(self):
        print('Waiting for connections on port %s' % (self.port))
        # We need to run a loop and create a new thread for each connection
        while True:
            conn, addr = self.server.accept()
            #users[addr[0] + ":" + addr[1]] = conn
            threading.Thread(target=self.run_thread, args=(conn, addr)).start()


def main():
    if len(sys.argv) < 2:
        print 'Usage: python server.py PORT'
        sys.exit(1)

    # dir = os.path.dirname(sys.argv[0])
    # if dir == '':
    #     dir = os.curdir

    # Initialize Context
    # ctx = SSL.Context(SSL.TLSv1_2_METHOD)
    # ctx.set_options(SSL.OP_NO_SSLv2)
    # ctx.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)
    # ctx.use_privatekey_file(os.path.join(dir, 'server.pkey'))
    # ctx.use_certificate_file(os.path.join(dir, 'server.cert'))
    # ctx.load_verify_locations(os.path.join(dir, 'CA.cert'))
    signal.signal(signal.SIGINT, signal_handler)
    server = Server(int(sys.argv[1]))
    server.run()

if __name__ == '__main__':
    main()
