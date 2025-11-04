import urllib
import os
import os.path
import json
import urllib.parse
import threading

import websockets.sync.server

from http.server import BaseHTTPRequestHandler, HTTPServer 
from random import randint

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
import base64

alphabet = "abcdefghijklmnopqrstuopqrstywvxyzABCDEFGHIJKLMNOPQRSTUOPQRSTYWVXYZ0123456789"
gen_random_string = lambda l: "".join([alphabet[randint(0,len(alphabet)-1)] for _ in range(l)])

class Session: 

    def __init__(self, key, public, peer_public) -> None:
        self.key=key
        self.public=public
        self.peer_public=peer_public
        self.authenticated=False

class SessionData:

    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(SessionData, cls).__new__(cls)
            cls.instance.init()

        return cls.instance

    def init(self):
        self.sessions:dict[str,Session]={}
    
    def add_session(self, session_id:str, session:Session):
        self.sessions[session_id] = session

    def get_session(self, session_id):
        return self.sessions.get(session_id)


class SocketServer:

    def __init__(self) -> None:
        self.cmd_table={
                "authenticate": self.authenticate_session,
        }

    def decrypt_message(self, msg, session:Session):
        # some things in this fuction do not need to be generated every time we decrypt. aead can be cached somewhere

        nonce = bytes([1,2,1,2,3,1,4,2,2,34,23,42]) # this needs to be handled somewhere not inline
        aead = AESGCM(session.key)

        m = bytes(list(msg))
        cleartext = aead.decrypt(nonce, m , None)
        print(cleartext.decode())
        return cleartext.decode()

    def handle_message(self, msg:str, session):
        try: ob = json.loads(msg)
        except: return
        self.cmd_table[ob["cmd"]](ob["content"], session)

    def handle_connection(self, ws: websockets.sync.server.ServerConnection):
        c_s = parse_cookies(ws.request.headers)
        
        while True:
            msg = ws.recv()

            if msg==None or msg=="": continue 

            if not (session_token:=c_s.get("session")):
                print("client does not have session")
                return

            if not (session := SessionData().get_session(session_token)):
                print("client has invalid session")
                return

            msg = self.decrypt_message(msg, session)
            if not msg: continue
            self.handle_message(msg, session)

    def start(self):
        port = 8889
        ws = websockets.sync.server.serve(self.handle_connection,"0.0.0.0",port)
        ws.serve_forever()

    def authenticate_session(self, msg, session:Session):
        if msg =="secret_key":
            session.authenticated=True
            print("authenticated session")


class Handler(BaseHTTPRequestHandler):

    static_path = "./static"

    def do_POST(self):
        routing_table = {
                "/setup_encryption":self.__pre_setup_encryption,
        }
        path = self.path.split('?')[0] 
        query_components = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        
        if path in routing_table:
            return routing_table[path](query_components)
  
    def do_GET(self):      
        routing_table = {
                "/":self.get_main,
                "/static":self.get_file,
        }
        
        parsed = urllib.parse.urlparse(self.path)
        query_components = urllib.parse.parse_qs(parsed.query)
        p = parsed.path.split("/")
        p.pop(0)
        
        search_path ="/"+p[0]
        print("query", p, search_path) 
        if search_path in routing_table:
            return routing_table[search_path](p, query_components)

    def send_404(self):
        self.send_response(404)

    def get_main(self, path, query):

        cookies = parse_cookies(self.headers)
        session = SessionData().get_session(cookies.get("session"))

        if session and session.authenticated:
            with open("./index.html") as f: data = f.read()
        else:
            with open("./login.html") as f: data = f.read()
        # if we have session cookie use that but if not generate one

        # send session token and stuff
        self.send_response(200)

        self.protocol_version = 'HTTP/1.0'
        self.send_header('content-type', 'text/html')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(data.encode())

    def get_file(self, path, query):
        # get file from static
        f_path = os.path.join(self.static_path, path[1])

        self.send_response(200)

        self.protocol_version = 'HTTP/1.0'
        self.send_header('content-type', 'text/js')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        with open(f_path) as f:
            data = f.read()
        self.wfile.write(data.encode())



    def __pre_setup_encryption(self,query):
        cookies = parse_cookies(self.headers)
        self.send_response(200)

        if not (session_token:=cookies.get("session")):
            session_token = gen_random_string(10)
            session = self.setup_encryption(query, session_token)
            c_string = "server_pub="+str(session.public.public_bytes_raw().hex("_"))

            self.send_header("Set-Cookie", "session="+session_token)
            self.send_header("Set-Cookie", c_string)
            self.send_header('Access-Control-Allow-Origin', '*')

        self.end_headers()

    def setup_encryption(self, query, session_token):
        # %TODO TEST AND VERIFY PROPPERLY THAT THIS IS EVEN CONSEPTUALLY SECURE
        # most of this code has been generated by chatgpt and i do not trust it 
        
        content_len = int(self.headers.get('Content-Length', 0))
        pub_b_bytes = self.rfile.read(content_len) 

        pub_b = base64.decodebytes(pub_b_bytes) # pubkey is in base64

        priv_a = x25519.X25519PrivateKey.generate()
        pub_a = priv_a.public_key() 

        shared_secret = priv_a.exchange(X25519PublicKey.from_public_bytes(pub_b))

        salt_str = "mysaltstring" # salt and info probably should not be here. they should be derived or generated at some point?
        info = b"sessionkeyv1"

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_str.encode(),
            info=info,
        )
        key = hkdf.derive(shared_secret)

        session=Session(key, pub_a, pub_b)
        SessionData().add_session(session_token, session) 
        return session

def parse_cookies(headers) :
    rv={}
    if cookies:=headers.get("Cookie"): 
        spl = cookies.split(";")
        # todo: dict comprehension here
        for i in spl:
            c= i.split("=")
            if len(c)>1:
                rv[c[0]] = c[1]

    return rv

def main():
    sock_server = SocketServer()
    socket_thread = threading.Thread(target=sock_server.start, daemon=True, name="sock thread")
    socket_thread.start()

    srvr = HTTPServer(('0.0.0.0', 8888), Handler)
    srvr.serve_forever()

if __name__ =="__main__": 
    main()
