import SocketServer
import BaseHTTPServer
import SimpleHTTPServer
import hashlib
import urlparse
import os, cgi
import sys
import socket
from OpenSSL import SSL

def verify_cb(conn, cert, errnum, depth, ok):
    # This obviously has to be updated
    print 'Got certificate: %s' % cert.get_subject()
    return ok

def gen_hash(data):
    m = hashlib.sha256()
    m.update(data)
    return m.hexdigest()

def mode_n(data):
    return data

CWD = os.path.abspath('.')

class CustomHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, 'rb', self.rbufsize)
        self.wfile = socket._fileobject(self.request, 'wb', self.wbufsize)

    def do_GET(self):
        url = urlparse.urlparse(self.path)
        filepath = url.path[1:] # remove leading '/'

        f = open( os.path.join(CWD, filepath), 'rb' )
        data = f.read()

        self.send_response(200)
        self.send_header('SHA256', gen_hash(data))
        self.send_header('Content-type', 'application/octet-stream')
        self.end_headers()

        self.wfile.write(data)

        f.close()
        return

    def do_POST(self):
        url = urlparse.urlparse(self.path)
        filepath = url.path[1:] # remove leading '/'
        f = open( os.path.join(CWD, "receive/" + filepath), 'wb' )

        ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))

        if ctype == 'multipart/form-data':
            query = cgi.parse_multipart(self.rfile, pdict)

        self.end_headers()

        uploadfilecontent = query.get(filepath)
        f.write(uploadfilecontent[0])
        f.close()

        self.wfile.write("%s uploaded" % filepath)
        print uploadfilecontent[0]

class ThreadingSimpleServer(SocketServer.ThreadingMixIn,
                   BaseHTTPServer.HTTPServer):
    def __init__(self, server_address, HandlerClass):
        SocketServer.BaseServer.__init__(self, server_address, HandlerClass)

        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2)
        ctx.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)
        fpem = 'server.pem'
        ctx.use_privatekey_file(fpem)
        ctx.use_certificate_file(fpem)
        ctx.load_verify_locations('client.pem')

        self.socket = SSL.Connection(ctx, socket.socket(self.address_family, self.socket_type))
        self.server_bind()
        self.server_activate()

    def shutdown_request(self,request): 
        request.shutdown()

if __name__ == '__main__':
    
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 8000

    server = ThreadingSimpleServer(('', port), CustomHandler)
    print "Server Listening on %d" % port
    try:
        server.serve_forever()
    except:
        print "Exiting..."
        sys.exit(1)