import socket
import time
import threading

from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
import hashlib

#note: server information subject to change. make sure to verify these values

LOGIN_IP = "158.69.121.176"
LOGIN_PORT = 3724

GAME_IP = "147.135.9.203"
GAME_PORT = 7034

class Client:

    def __init__(self, 
            username,
            password,
            login_ip=LOGIN_IP,
            login_port = LOGIN_PORT,
            game_ip = GAME_IP,
            game_port = GAME_PORT):

        self.username = username
        self.password = password
        
        #game variables
        self.penguin_id = None

        self.login_ip = login_ip
        self.login_port = login_port
        self.login_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.game_ip = game_ip
        self.game_port = game_port
        self.game_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.magic = "a1ebe00441f5aecb185d0ec178ca2305Y(02.>\'H}t\":E1_root"
        self.verchk_msg = "<msg t='sys'><body action='verChk' r='0'><ver v='153' /></body></msg>"
        self.rndk_msg = "<msg t='sys'><body action='rndK' r='-1'></body></msg>" 
        self.login_msg = '<msg t="sys"><body action="login" r="0"><login z="w1"><nick><![CDATA['+self.username+']]></nick><pword><![CDATA[{}]]></pword></login></body></msg>'


        self.key = None
        self.rndk = None
        self.login_key = None
        self.user_packet = None
        self.user_packet2 = None
        

    def _send(self,sock,payload,encrypted=True):
        if(encrypted):
            payload = hexlify(AES.new(self.key, AES.MODE_ECB).encrypt(self._pkcs7_pad(payload,16))).decode('utf-8')
        else:
            payload += chr(0)

        sock.send(payload.encode())
    
    ##CRYPTO HELPERS
    def _pkcs7_pad(self,data, block_size):
        padding_length = block_size - len(data) % block_size
        return data + chr(padding_length) * padding_length

    def _AESdecrypt(self,msg):
        msg = msg.replace(b'\x00',b'')
        barr = bytearray(msg)
        return AES.new(self.key,AES.MODE_ECB).decrypt(unhexlify(bytes(barr)))

    def encryptPassword(self,password):
        _hashed = hashlib.md5(password.encode())
        _hashed = _hashed.hexdigest()
        return _hashed[16:32] + _hashed[:16]

    ##CMD INTERPRETER

    ##LOGIN HANDSHAKE

    def extract_rndk(self,msg):
        return msg[msg.find("<k>")+3:msg.find("</k>")]

    def login(self):
        print("[CLIENT] connecting to login server")
        self.login_socket.connect((self.login_ip, self.login_port))

        #request AES encryption key
        self._send(self.login_socket, self.verchk_msg, encrypted=False)
        self.key = self.login_socket.recv(1024).decode('utf-8').split("#")[2]

        #request hash key 
        self._send(self.login_socket, self.rndk_msg)
        encrypted_reply = self.login_socket.recv(1024)
        
        self.rndk = (self.extract_rndk(self._AESdecrypt(encrypted_reply).decode('utf-8')))
    
        #send login request
        loc1 = self.encryptPassword(self.password).upper()
        loc1 = loc1 + self.rndk
        loc1 = loc1 + self.magic
        loc1 = self.encryptPassword(loc1)
        self._send(self.login_socket,self.login_msg.format(loc1))

        print("[CLIENT] sending login request")

        buf = b""
        #TODO: fix this temp solution
        while len(buf) < 6400:
            buf += self.login_socket.recv(1024)

        #TODO: parse the information before this
        init_resp = self._AESdecrypt(buf).decode('utf-8')

        userInfo = init_resp[init_resp.find("%xt%l%-1%")+9:].split("|")

        self.penguin_id = userInfo[0]
        self.login_key = userInfo[3]

        self.user_packet = init_resp[init_resp.find("%xt%l%-1%")+9:].split("%")[0]
        self.user_packet2 = init_resp[init_resp.find("%xt%l%-1%")+9:].split("%")[1]

    ##GAME HANDSHAKE
    def join_world(self,roomID = "100"):

        print("[CLIENT] connecting to game server")

        self.game_socket.connect((self.game_ip,self.game_port))

        #send vercheck
        self._send(self.game_socket, self.verchk_msg,False)
        #request random key
        self._send(self.game_socket, self.rndk_msg,False)

        buf = b""
        while 1:

            buf = buf + self.game_socket.recv(4096)
            delim = buf.find(b'\x00')
            
            while delim!=-1:

                cmd = buf[:delim].decode('utf-8')
                #use cmd to interpret individual commands from CPOnline servers

                print("[CPOnline] " + cmd)


                if ("rndK" in cmd):
                    self.rndk = self.extract_rndk(cmd)

                    print("[CLIENT] joining world")

                    #send login request to the game
                    login_code = self.encryptPassword(self.login_key + self.rndk) + self.login_key

                    payload = "<msg t='sys'><body action='login' r='0'><login z='w1'><nick><![CDATA[{}]]></nick><pword><![CDATA[{}]]></pword></login></body></msg>"
                    payload = payload.format(self.user_packet, login_code + "#" + self.user_packet2)
                    self._send(self.game_socket, payload ,False)

                    cmd = self.game_socket.recv(4096)


                    pa = "%xt%s%j#js%-1%{}%{}%en%".format(self.penguin_id,self.login_key)
                    self._send(self.game_socket,pa,False)
                    print("[CLIENT] success, connected to the game!\n\n")
                    time.sleep(2)
                    # finish handshake

                buf = buf[delim+1:]
                delim = buf.find(b'\x00')


client = Client(username="username",password="password")
client.login()
client.join_world()




    






    

