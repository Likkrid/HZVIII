#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from Crypto.Util.number import *
import SocketServer,string,signal,random,sys

PORT = 6776

p = 169190849908171023288307339044530660251053691880472974308588587669108393339479218343467606959873557652028796331630894148101895749038501058026903394542693227061956193960988086687175451732633751931097670564771615055986238919767344273578222753486514961292954087400823074165260390884832213999754832198100883152817
q = 109428029649440430724985328440426800088095512795047844765497650150300167758617620285912074886715196546316654722962451425382958488866875211874405557040233022812316149661256784075369885622582466551711782792964231138949677143512586814879652448516728832311262378696530387109817059014697289977596289928808870560521
r = 28324228239363374596194831603892272765727935024801683641238831323425191843497399356113972653282785821445234526607381395724909846914957106058244321651826693574257510573656400163170422624552961721577807397112275802706888482667684303788820139172010927871675237895870362714635301376080466880238223417751435854652464694778418228850337952011455340246224617747303090930130568062616483524260986660013661622929386103302423390900287566404575267019924851268350001130408444267784904813657390464859088902327337540317280115899553958900970608889557148594099762075034121853284539269993839507653071747630042882785844835860744926287513
n = p*q*r

flag = "HZVIII{Ton3ll1_5haNkS_&_CRT_SM4sH3d_RabiN_3_SqUar3_R0o7s}"

class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream
    def write(self, data):
        self.stream.write(data)
        self.stream.flush()
    def writelines(self, datas):
        self.stream.writelines(datas)
        self.stream.flush()
    def __getattr__(self, attr):
        return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)

class incoming(SocketServer.BaseRequestHandler):

    def handle(self):
        req = self.request

        def recvline():
            buf = ""
            while not buf.endswith("\n"):
                buf += req.recv(1)
            return buf

        def encrypt():
            req.send ("> Encryption:\nSend me some data to encrypt:\n")
            data = recvline().strip()
            req.send ("> Your encrypted message:\n")
            req.send (str(bytes_to_long(data)**2%n)+"\n")

        def decrypt():
            random.seed()
            secret = ''.join(random.choice(string.punctuation + string.digits + string.letters) for _ in range(500))
            cipher = bytes_to_long(secret)**2%n
            req.send ("> Decrypt this message and the flag is yours:\n" + str(cipher) + "\n>Waiting for decrypted message:\n")
            decrypted = recvline().strip()
            if decrypted == secret:
                req.send("> You defeated me here is your flag: "+ flag)
                sys.exit(1)
            else:
                req.send("> Naah !\n")




        def welcome():
            req.sendall("""
   +---------------------------------------------------------
   :". /  /  /
   :.-". /  /
   : _.-". /
   :"  _.-".
   :-""     ".   Welcome to the RootCrypto Challenge ..
   :
   :
 ^.-.^
'^\+/^`
'/`"'\`
\n""")

        def menu():
            req.send ("\n\tMenu:\n")
            req.send ("\t [*] E[n]crypt your message {take it easy this is a beta version}\n")
            req.send ("\t [*] D[e]crypt one of our random secret messages to get the flag\n")
            req.send ("\t [*] E[x]it\n")
            while True:
                choice = recvline().strip()
                if choice in list('nex'):
                    return choice
                else:
                    return 0


        #Session length
        signal.alarm(100)

        welcome()
        while True:
            choice = menu()
            if choice == 'n':
                encrypt()
            elif choice == 'e':
                decrypt()
            elif choice == 'x':
                req.send ("Bye, hack carefully come back soon..")
                sys.exit(1)
            else:
                req.send ("Y u do dis to meh?")
                sys.exit(1)

class ReusableTCPServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
  pass

SocketServer.TCPServer.allow_reuse_address = True
server = ReusableTCPServer(("0.0.0.0", PORT), incoming)

print ("Server listening on port %d" % PORT)
server.serve_forever()
