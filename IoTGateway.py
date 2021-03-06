from scapy.all import *
from uuid import getnode as get_mac
from subprocess import check_output
import socket
import time
import threading
import thread
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
    def checkPermission(self, methodname,object_name,resource,action):

        
        rule = iptc.Rule()
        rule.in_interface = "wlan0"
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain2 = iptc.Chain(iptc.Table(iptc.Table.FILTER), "FORWARD")
        
        chain.flush()
        chain2.flush()
        
        while True:
            time.sleep(10)
            try:

                url = "http://180.189.90.200:9322/api/v1/lookUpTables/object?macAddress=B8:27:EB:4A:D0:FB"
                header = {'orgAffiliation':'userOrg','orgMspId':'UserOrgMSP', 'Content-Type':'application/json'}
                    
                response = requests.get(url, headers = header, timeout=3)
                    #rs_code = response.status_code
                    
                    # -----------------------------------------------------------------------------------------------
                nMap = response.json()
                    
                    #print(nMap)
                    
                tempMap = []
                
                
                
                #print(self.networkMap)
                
                for obj in nMap['objects']:
                    #print(obj)
                    tempMap.append([obj['macAddress'], obj['policyId'], False])
                    

                    
                for i in tempMap:
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
                        
                print(tempMap)
                print(self.networkMap)
                        
                if tempMap != self.networkMap:
                    print("AAAACCCCCCCCCCCCCCCCcc")
                    self.networkMap = tempMap
                    chain.flush()
                    chain2.flush()
                            
                    #print(self.networkMap)
                        
                    rule2 = iptc.Rule()
                    rule2.in_interface = "wlan0"
                    rule2.target = iptc.Target(rule2, "DROP")
                    rule2.protocol = "tcp"
             
                    chain.insert_rule(rule2)
                    
                    
                    rule2 = iptc.Rule()
                    rule2.in_interface = "wlan0"
                    rule2.target = iptc.Target(rule2, "DROP")
                    rule2.protocol = "udp"
                    match = rule2.create_match("udp")
                    match.dport = "!67"
                    rule2.add_match(match)
                                        
                    chain.insert_rule(rule2)
                    
                    
                    
                    
                    rule2 = iptc.Rule()
                    rule2.in_interface = "wlan0"
                    rule2.target = iptc.Target(rule2, "DROP")
                                        
                    chain2.insert_rule(rule2)
                    
                        
                        #print(rule2.protocol)
                    
                    for i in self.networkMap:
                        if i[2] == True:
                            rule = iptc.Rule()
                            rule.in_interface = "wlan0"
                            
                            match = iptc.Match(rule, "mac")
                            match.mac_source = i[0].encode('utf8')                       
                            rule.add_match(match)
                            rule.target = iptc.Target(rule, "ACCEPT")
                                
                            chain.insert_rule(rule)
                            
                            rule = iptc.Rule()
                            rule.in_interface = "wlan0"
                            
                            match = iptc.Match(rule, "mac")
                            match.mac_source = i[0].encode('utf8')                       
                            rule.add_match(match)
                            rule.target = iptc.Target(rule, "ACCEPT")
                                
                            chain2.insert_rule(rule)
                            
                            #print(i[0].encode('utf8'), type(i[0].encode('utf8')))
                            
                    #time.sleep(100) # BlockChain request delay
                            
            except requests.Timeout:
                pass
            except requests.ConnectionError:
                pass
            
            for i in iptc.easy.dump_chain('filter', 'INPUT'):
                print(i)
                            
                print("")
                            
            for i in iptc.easy.dump_chain('filter', 'FORWARD'):
                print("AAAAAAAAA")
                print(i)
                

            

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