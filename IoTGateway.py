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
import iptc

global allow1

global acceptT
acceptT = 0
global denyT
denyT = 0

print("KKKKK")

class IoTGateway:
    
    macAddr = ""
    ipAddr = ""
    gatewayMac = ""
    gatewayIP = ""

    networkMap = []

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

    
        
        rule = iptc.Rule()
        rule.in_interface = "wlan0"
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        while True:
            try:
                chain.flush()
                url = "http://180.189.90.200:9322/api/v1/lookUpTables/object?macAddress=B8:27:EB:4A:D0:FB"
                header = {'orgAffiliation':'userOrg','orgMspId':'UserOrgMSP', 'Content-Type':'application/json'}
                    
                response = requests.get(url, headers = header, timeout=3)
                    #rs_code = response.status_code
                    
                    # -----------------------------------------------------------------------------------------------
                nMap = response.json()
                    
                    #print(nMap)
                    
                self.networkMap = []
                
                for obj in nMap['objects']:
                    #print(obj)
                    self.networkMap.append([obj['macAddress'], obj['policyId'], False])
                        
                for i in self.networkMap:
                    try:
                        url = "http://180.189.90.200:9322/api/v1/accessControl?id="+i[1]
                        response = requests.get(url, headers = header, timeout=3)
                            
                        #print(url)
                        permission = response.status_code
                            
                        if permission == 200:
                            i[2] = True
                            
                        else:
                            i[2] = False
                        
                    except:
                        print("some error")
                        
                print(self.networkMap)
                    
                 
                    #print(len(chain.rules))
                    
                
                rule2 = iptc.Rule()
                rule2.in_interface = "wlan0"
                rule2.target = iptc.Target(rule2, "DROP")
                rule2.protocol = "tcp"
                    #match = rule2.create_match("tcp")
                    #match.dport = "!4000"
                    #rule2.add_match(match)


                    
                chain.insert_rule(rule2)
                
                
                rule2 = iptc.Rule()
                rule2.in_interface = "wlan0"
                rule2.target = iptc.Target(rule2, "DROP")
                rule2.protocol = "udp"
                match = rule2.create_match("udp")
                match.dport = "!67"
                rule2.add_match(match)
                                    
                chain.insert_rule(rule2)
                
                    
                    #print(rule2.protocol)
                
                for i in self.networkMap:
                    if i[2] == True:
                        rule = iptc.Rule()
                        rule.in_interface = "wlan0"
                        
                        match = iptc.Match(rule, "mac")
                        match.mac_source = i[0]       
                        
                        rule.add_match(match)
                        rule.target = iptc.Target(rule, "ACCEPT")
                            
                        chain.insert_rule(rule)
                        
                        print(i[0].encode('utf8'), type(i[0].encode('utf8')))
                        

                    
                    #print(table.name)                    
                    #print(len(chain.rules))
                    
                for i in iptc.easy.dump_chain('filter', 'INPUT'):
                    print(i)
                        
                time.sleep(10) # BlockChain request delay
                        
                    
                    # -----------------------------------------------------------------------------------------------
                    #print(response.json())
                    #if int(rs_code) == 200:
                    #    self.networkMap[object_macAddr][1] = True
                    #    print(rs_code)

                    #else:
                    #    self.networkMap[object_macAddr][1] = False
                        
            except requests.Timeout:
                pass
            except requests.ConnectionError:
                pass
                

            

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
            
                r = pyping.ping(baseIp + str(ipIndex), timeout=1)
                
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

    #gateway.networkMap['objects'] = [{'macAddress':"58:96:1d:62:14:a7", "name": "laptop"}] # TEST IP, MAC

    #threading._start_new_thread(gateway.setNetworkMap, (ip,))
    threading._start_new_thread(gateway.checkPermission, ("Yu205","myPc","Test","connect"))
    #threading._start_new_thread(gateway.accessControl, ())
    
    while True:
        time.sleep(100)

