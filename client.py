import os, sys, socket, select, binascii, signal, threading, ushlex, cmd, datetime

def signal_handler(signal, frame):
    print "Exiting..."
    os._exit(1)

def mode_n(data):
        return data

class Client(cmd.Cmd):
    sock = None
    datasock = None
    prompt = '>'
    modes = {
                'N': mode_n,

            }

    def do_EOF(self, line):
        return True

    def do_stop(self):
        signal_handler()
        return

    def do_get(self, line):
        args = ushlex.split(line)
        file_name = args[0]
        mode = args[1]

        self.sock.sendall('get %s %s' % (file_name, mode))
        f = open(file_name + str(datetime.datetime.now()), 'wb')
        h = open(file_name + '.sha256', 'wb')

        stage = None
        while True:
            data = self.sock.recv(4096)
            print data
            string = bytes.decode(data)
            args = ushlex.split(string)
            print args


            if (args[0] == 'GET' or args[0] == 'SHA'):
                length = args[4]
                l = 0
                while l < length:
                    data = self.sock.recv(4096)
                    if (args[0] == 'GET'):
                        f.write(data)
                    if (args[0] == 'SHA'):
                        h.write(data)
                    l += sys.getsizeof(data)
                f.close()
                h.close()
                return

        print "%s received" % file_name



    def set_sock(self, sock):
        self.sock = sock

    def set_datasock(self, sock):
        self.datasock = sock




if __name__ == '__main__':

    if len(sys.argv) < 3:
        print 'Usage: python client.py HOST PORT'
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect to remote host
    try :
        s.settimeout(2)
        s.connect((sys.argv[1], int(sys.argv[2])))
    except :
        print 'Unable to connect'
        sys.exit()

    client = Client()
    client.set_sock(s)
    client.cmdloop()

    s.close()
    sys.exit()
