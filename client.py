import sys, socket, select, binascii, signal, threading, ushlex

def signal_handler(signal, frame):
    sys.exit(0)

def prompt() :
    sys.stdout.write('> ')
    sys.stdout.flush()

if __name__ == '__main__':
    
    signal.signal(signal.SIGINT, signal_handler)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    f = open('recv.dat', 'wb')

# connect to remote host
    try :
        s.connect(('localhost', 5555))
    except :
        print 'Unable to connect'
        sys.exit()
     
    prompt()

    while 1:
        socket_list = [sys.stdin, s]
             
        # Get the list sockets which are readable
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])

        for sock in read_sockets:
                    #incoming message from remote server
                    if sock == s:
                        data = sock.recv(4096)
                        if data == 'GET':
                            print "closing file"
                            f.close()
                            prompt()
                        if data and data != 'GET':
                            print "writing to file"
                            f.write(binascii.hexlify(data))
                            
                    #user entered a message
                    else :
                        msg = sys.stdin.readline()
                        s.sendall(msg)
                        prompt()
    s.close()
    sys.exit()
