import SocketServer
import BaseHTTPServer
import SimpleHTTPServer
import hashlib
import urlparse
import os, cgi
import sys

def gen_hash(data):
    m = hashlib.sha256()
    m.update(data)
    return m.hexdigest()

def mode_n(data):
    return data

CWD = os.path.abspath('.')

class CustomHandler(BaseHTTPServer.BaseHTTPRequestHandler):

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
    pass

if sys.argv[1:]:
    port = int(sys.argv[1])
else:
    port = 8000

server = ThreadingSimpleServer(('', port), CustomHandler)
try:
    while 1:
        sys.stdout.flush()
        server.handle_request()
except KeyboardInterrupt:
    print "Finished"