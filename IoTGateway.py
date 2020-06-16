from scapy.all import *
from uuid import getnode as get_mac
from subprocess import check_output
import socket
import time
import threading
import thread
global allow1

global acceptT
acceptT = 0
global denyT
denyT = 0
class IoTGateway:
    
    macAddr = ""
    ipAddr = ""
    networkMap = {}
    port = 8888
    
    def __init__(self, macAddr, ipAddr):
        temp = ""
        
        for i in range(len(macAddr)):
            temp += macAddr[i]
            if i != 0 and i % 2 == 1 and i != len(macAddr)-1:
                temp += ':'
        
        self.macAddr = temp
        self.ipAddr = ipAddr[0:15]
        
        print(self.macAddr, self.ipAddr)
    
    def denyAccess(self):
        
        global denyT
        if denyT == 2:
            return

        global allow1
        allow1 = 'false'
        
        while True:
            print("deny")
            if allow1 == 'true':
                break
            time.sleep(1)
            send(ARP(op=2, pdst = self.networkMap[userMAC], psrc = self.ipAddr[:10]+'1', hwsrc = "11:22:33:44:55:66",hwdst = userMAC), verbose = 0)
        denyT -= 1
        
    def acceptAccess(self):
        
        global acceptT
        
        if acceptT == 2:
            return

        global allow1
        allow1 = 'true'
        while True:
            print("accept")
            if allow1 == 'false':
                break
            time.sleep(1)
            send(ARP(op=2, pdst = self.networkMap[userMAC], psrc = self.ipAddr[:10]+'1', hwdst = userMAC), verbose = 0)
            send(ARP(op=2, pdst = self.ipAddr[:10]+'1', psrc = self.networkMap[userMAC], hwdst = "08:10:77:13:dd:0b"), verbose = 0)
        acceptT -= 1
            
    def waitAccess(self, userMAC):
        while True:
            send(ARP(op=2, pdst = self.networkMap[userMAC], psrc = self.ipAddr[:10]+'1', hwdst = userMAC), verbose = 0)
            #send(ARP(op=2, pdst = self.ipAddr[:10]+'1', psrc = self.networkMap[userMAC], hwdst = "08:10:77:13:dd:0b"), verbose = 0)
            time.sleep(1)
        
    def connectAccess(self):
        
        
        global allow1
        global acceptT
        global denyT

        allow1 = 'false'    
        denyT += 1
        threading._start_new_thread(self.denyAccess, ())


        while True:
            
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            ADDR = ("", self.port)
            
            server_sock.bind(ADDR)
            server_sock.listen(100)
            client, addr = server_sock.accept() 
            k = client.recv(1024)
            if k != '':
                allow1 = k
            print('main',k, type(k))

            if allow1 == 'true':
                print(allow1)
                acceptT +=1
                threading._start_new_thread(self.acceptAccess, ())
                
                
            elif allow1 == 'false':
                print(allow1)
                denyT += 1
                threading._start_new_thread(self.denyAccess, ())
                
        server_sock.close()
            

mac = str(hex(get_mac()))
mac = mac[2:-1]

ip = str(check_output(['hostname','-I']))

gateway = IoTGateway(mac, ip)

userMAC = "34:a8:eb:ec:e2:64"
penalty = 20

gateway.networkMap['34:a8:eb:ec:e2:64'] = '192.168.1.14'

#waitThread = threading.Thread(target = gateway.waitAccess, args = [userMAC])
#waitThread.start()

#denyThread = threading.Thread(target = gateway.denyAccess(), args='')
#denyThread.start()

gateway.connectAccess()

#connectThread = threading.Thread(target = gateway.connectAccess, args = "")
#connectThread.start()

#connectThread.join()