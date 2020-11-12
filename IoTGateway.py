from scapy.all import *
from uuid import getnode as get_mac
from subprocess import check_output
import socket
import time
import threading
import thread
#import flask
import requests
import json
import pyping

global allow1

global acceptT
acceptT = 0
global denyT
denyT = 0



class IoTGateway:
    
    macAddr = ""
    ipAddr = ""
    gatewayMac = ""
    gatewayIP = ""

    networkMap = {}

    #port = 8888
    
    def __init__(self, macAddr, ipAddr, gatewayMac, gatewayIP):
        temp = ""
        
        for i in range(len(macAddr)):
            temp += macAddr[i]
            if i != 0 and i % 2 == 1 and i != len(macAddr)-1:
                temp += ':'
        
        self.macAddr = temp
        self.ipAddr = ipAddr
        self.gatewayMac = gatewayMac
        self.gatewayIP = gatewayIP
    
    # def denyAccess(self):
        
    #     global denyT
    #     if denyT == 2:
    #         return

    #     global allow1
    #     allow1 = 'false'
        
    #     while True:
    #         print("deny")
    #         if allow1 == 'true':
    #             break
    #         time.sleep(1)


            
    #         send(ARP(op=2, pdst = '192.168.75.1', psrc = '192.168.75.150', hwsrc = "11:22:33:44:55:66",hwdst = '00:50:56:C0:00:08'), verbose = 0)


    #         #send(ARP(op=2, pdst = self.networkMap['00:50:56:C0:00:08'], psrc = self.gatewayIP, hwsrc = "11:22:33:44:55:66",hwdst = userMAC), verbose = 0)
    #     denyT -= 1
        
    # def acceptAccess(self):
        
    #     global acceptT
        
    #     if acceptT == 2:
    #         return

    #     global allow1
    #     allow1 = 'true'
    #     while True:
    #         print("accept")
    #         if allow1 == 'false':
    #             break
    #         time.sleep(1)
    #         send(ARP(op=2, pdst = self.networkMap[userMAC], psrc = self.gatewayIP, hwdst = userMAC), verbose = 0)
    #         send(ARP(op=2, pdst = self.gatewayIP, psrc = self.networkMap[userMAC], hwdst = gatewayMac), verbose = 0)
    #         #need to change macAddress

    #     acceptT -= 1
            
    # def waitAccess(self, userMAC):
    #     while True:
    #         send(ARP(op=2, pdst = self.networkMap[userMAC], psrc = self.gatewayIP, hwdst = userMAC), verbose = 0)
    #         #send(ARP(op=2, pdst = self.ipAddr[:10]+'1', psrc = self.networkMap[userMAC], hwdst = "08:10:77:13:dd:0b"), verbose = 0)
    #         time.sleep(1)
        
    # def connectAccess(self):
    #     global allow1
    #     global acceptT
    #     global denyT

    #     allow1 = 'false'    
    #     denyT += 1
    #     threading._start_new_thread(self.denyAccess, ())


    #     while True:
            
    #         server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
    #         ADDR = ("", self.port)
            
    #         server_sock.bind(ADDR)
    #         server_sock.listen(100)
    #         client, addr = server_sock.accept() 
    #         k = client.recv(1024)

    #         if k != '':
    #             allow1 = k
    #         print('main',k, type(k))

    #         if allow1 == 'true':
    #             print(allow1)
    #             acceptT +=1
    #             threading._start_new_thread(self.acceptAccess, ())
                
                
    #         elif allow1 == 'false':
    #             print(allow1)
    #             denyT += 1
    #             threading._start_new_thread(self.denyAccess, ())
                
    #     server_sock.close()

    # def userPage(self):
    #     #After connect Blockchain
        
    #     if(permission == False):
    #         return userpage

    def checkPermission(self, methodname,object_name,resource,action):
        url = "http://36.38.56.78:9322/api/v1/accessControl"
        header = {'Content-Type':'application/json; charset=utf-8', 'orgAffiliation':'userOrg','orgMspId':'UserOrgMSP'}
        
        while True:
            for object_macAddr in self.networkMap.keys():
                datas = {
                    "methodName":methodname,
                    "object":{"name":object_name , "macAddress":object_macAddr},
                    "resource":resource,
                    "action":action
                }
                
                try:
                    response = requests.post(url, headers = header, data=json.dumps(datas), timeout=1)
                    rs_code = response.status_code
                    
                    if int(rs_code) == 200:
                        self.networkMap[object_macAddr][1] = True
                        print(rs_code)

                    else:
                        self.networkMap[object_macAddr][1] = False
                        
                except requests.Timeout:
                    self.networkMap[object_macAddr][1] = False
                except requests.ConnectionError:
                    self.networkMap[object_macAddr][1] = False

            time.sleep(5) # BlockChain request delay

    def accessControl(self):
        while True:
            for mac in self.networkMap.keys():
                if self.networkMap[mac][1] == True:
                    print(self.networkMap[mac][0]+" is Accept")
                    continue

                else:
                    print(self.networkMap[mac][0]+" is Denied")
                    #send(ARP(op=2, pdst = self.gatewayIP, psrc = self.networkMap[mac][0], hwsrc = "AA:AA:AA:BB:BB:BB",hwdst = self.gatewayMac), verbose = 0)
                    send(ARP(op=2, pdst = self.networkMap[mac][0], psrc = self.gatewayIP, hwsrc = mac,hwdst = mac), verbose = 0)

            time.sleep(1) # ARP Send Frequency

    def getNetworkMap(self, ipAddress):
        for mac in self.networkMap.keys():
            if self.networkMap[mac][0] == ipAddress:
                return mac

        return None

    def getMacAddr(self, ip):
        print("AAAAAAAAAAAAAAA")
        arp_req_frame = ARP(pdst = ip)

        broadcast_ether_frame = Ether(dst = "ff:ff:ff:ff:ff:ff")
        
        broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

        answered_list = srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]
        result = []
	client_dict = {}
        
        for i in range(0,len(answered_list)):
        	client_dict = {"ip" : answered_list[i][1].psrc, "mac" : answered_list[i][1].hwsrc}
        	result.append(client_dict)
        
        self.networkMap[client_dict["mac"]] = [ip, False]

    def setNetworkMap(self, ip):

        baseIp = ip[:ip.rfind(".")+1]
        
        #print([baseIp])

        while True:
            for ipIndex in range(1, 255):
                
                #print(self.networkMap, ipIndex)
                
                #print(baseIp + str(ipIndex))

                if baseIp + str(ipIndex) == ip or baseIp + str(ipIndex) == self.gatewayIP:
                    continue
                
                print([baseIp + str(ipIndex)])
            
                r = pyping.ping(baseIp + str(ipIndex))
                
                print(ipIndex)

                if r.ret_code == 0:
                    print("ccccccc")
                    self.getMacAddr(baseIp+str(ipIndex))

                #time.sleep(3)

if __name__ == '__main__':

    mac = str(hex(get_mac()))
    mac = mac[2:-1]

    ip = str(check_output(['hostname','-I']))
    ipIndex = ip.rfind(".")+1
    ipTemp = ip[ipIndex:-2]
    ip = ip[:ipIndex] + ipTemp
    
    print("myIP : ", ip)

    gatewayInfo = str(check_output(['arp', '-a']))
    gatewayInfo = gatewayInfo.split("\n")

    gatewayMac = ""
    gatewayIP = ""

    for info in gatewayInfo:
        if "DESKTOP" in info:
            macIdx = info.rfind("at") + 3
            gatewayMac = info[macIdx:macIdx+17]

            ipIdx1 = info.rfind("(")+1
            ipIdx2 = info.rfind(")")
            gatewayIP = info[ipIdx1:ipIdx2]

            break
        
    print("my MAC :", mac)
    print("gatewayMAC :", gatewayMac)
    print("gatewayIP :", gatewayIP)

    gateway = IoTGateway(mac, ip, gatewayMac, gatewayIP)

    #userMAC = "00:0c:29:f2:90:e6"
    #penalty = 20

    gateway.networkMap['34:a8:eb:ec:e2:64'] = ['192.168.1.14', True] # TEST IP, MAC

    threading._start_new_thread(gateway.setNetworkMap, (ip,))
    threading._start_new_thread(gateway.checkPermission, ("Yu205","myPc","Network","connect"))
    threading._start_new_thread(gateway.accessControl, ())
    
    while True:
        time.sleep(100)

#a = gateway.checkPermission()
#print(a)

#waitThread = threading.Thread(target = gateway.waitAccess, args = [userMAC])
#waitThread.start()

#denyThread = threading.Thread(target = gateway.denyAccess(), args='')
#denyThread.start()

#gateway.connectAccess()

#connectThread = threading.Thread(target = gateway.connectAccess, args = "")
#connectThread.start()

#connectThread.join()

