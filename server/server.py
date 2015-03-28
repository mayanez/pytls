import SocketServer
import BaseHTTPServer
import SimpleHTTPServer
import urlparse
import os, cgi
import sys
import socket
from OpenSSL import SSL

def verify_cb(conn, cert, errnum, depth, ok):
    try:
        conn.check_privatekey()
    except:
        return -1;
    print 'Certificate: %s' % cert.get_subject()
    return ok

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

        if (not os.access(filepath, os.R_OK)):
            self.send_reponse(404)
            self.wfile.write("No permissions")

        #check if file exists first. If doesnt through 404
        if (os.path.isfile(filepath) and os.path.isfile(filepath + '.sha256')):
            f = open(filepath, 'rb' )
            h = open(filepath + '.sha256', 'rb')
            data = f.read()
            data_hash = h.read()

            self.send_response(200)
            self.send_header('SHA256', data_hash)
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()

            self.wfile.write(data)

            f.close()
            h.close()
        else:
            self.send_response(404)
            self.wfile.write("Not a file or does not contain .sha256")

        return

    def do_POST(self):
        url = urlparse.urlparse(self.path)
        filepath = url.path[1:] # remove leading '/'
        f = open(filepath, 'wb' )
        h = open(filepath + ".sha256", 'wb')

        data_hash = urlparse.parse_qs(url.query)['hash'][0]
        h.write(data_hash)
        h.close()

        ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))

        if ctype == 'multipart/form-data':
            query = cgi.parse_multipart(self.rfile, pdict)

        self.end_headers()

        uploadfilecontent = query.get(filepath)
        f.write(uploadfilecontent[0])
        f.close()

        self.wfile.write("%s uploaded" % filepath)
        print "%s uploaded" % filepath

class ThreadingSimpleServer(SocketServer.ThreadingMixIn,
                   BaseHTTPServer.HTTPServer):
    def __init__(self, server_address, HandlerClass, cert, key, ca_cert):
        SocketServer.BaseServer.__init__(self, server_address, HandlerClass)

        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2)
        ctx.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)
        ctx.use_privatekey_file(key)
        ctx.use_certificate_file(cert)
        ctx.load_verify_locations(ca_cert)

        self.socket = SSL.Connection(ctx, socket.socket(self.address_family, self.socket_type))
        self.server_bind()
        self.server_activate()

    def finish_request(self, request, client_address):
        try:
            return BaseHTTPServer.HTTPServer.finish_request(self, request, client_address)
        except:
            print 'Error processing incoming request. Verify Certificates.'

    def shutdown_request(self,request):
        request.shutdown()

if __name__ == '__main__':

    if len(sys.argv) < 5:
        print 'Usage: python server.py PORT SERVER_CERT SERVER_KEY CA_CERT'
        sys.exit(1)

    port = int(sys.argv[1])

    server = ThreadingSimpleServer(('', port), CustomHandler, sys.argv[2], sys.argv[3], sys.argv[4])
    print "Server Listening on %d" % port


    try:
        server.serve_forever()
    except:
        print "Exiting..."
        sys.exit(1)