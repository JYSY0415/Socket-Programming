import time
import requests
import json
import iptc
import sys
import netifaces
import os

class IoTGateway:
    networkMap = []

    networkInterface = ""
    webServer = ""
    macAddr = ""
    webPort = ""

    def __init__(self, networkInterface, webServer, macAddr, webPort):
        self.networkInterface = networkInterface
        self.webServer = webServer
        self.macAddr = macAddr
        self.webPort = webPort

    def getNetworkMap(self):
        try:
            url = "http://" + self.webServer + ":" + self.webPort + "/api/v1/lookUpTables/object?macAddress=" + self.macAddr
            header = {'orgAffiliation':'userOrg','orgMspId':'UserOrgMSP', 'Content-Type':'application/json'}
        
            response = requests.get(url, headers = header, timeout=3)

            return response.json()

        except:
            os.system("systemctl stop hostapd")
            os.system("systemctl stop dnsmasq")
            sys.exit("[!] Failed to get user list from web server")

    def getPermission(self, networkMap):
        for user in networkMap:
            try:
                url = "http://" + self.webServer + ":9322/api/v1/accessControl?id=" + user[1]
                header = {'orgAffiliation':'userOrg','orgMspId':'UserOrgMSP', 'Content-Type':'application/json'}

                response = requests.get(url, headers = header, timeout=3)

                permission = response.status_code
                                
                if permission == 200:
                    user[2] = True
                                
                else:
                    user[2] = False

            except:
                os.system("systemctl stop hostapd")
                os.system("systemctl stop dnsmasq")
                sys.exit("[!] Failed to get permission from web server")

        return networkMap

    def resetChain(self, inputChain, forwardChain):
        inputChain.flush()
        forwardChain.flush()

    def setDrop(self, inputChain, forwardChain):
        rule = iptc.Rule()
        rule.in_interface = self.networkInterface
        rule.target = iptc.Target(rule, "DROP")
        rule.protocol = "tcp"
             
        inputChain.insert_rule(rule)
                    
        rule = iptc.Rule()
        rule.in_interface = self.networkInterface
        rule.target = iptc.Target(rule, "DROP")
        rule.protocol = "udp"

        match = rule.create_match("udp")
        match.dport = "!67"

        rule.add_match(match)
                                        
        inputChain.insert_rule(rule)
                
        rule = iptc.Rule()
        rule.in_interface = self.networkInterface
        rule.target = iptc.Target(rule, "DROP")
                                        
        forwardChain.insert_rule(rule)

    def setAccept(self, inputChain, forwardChain):
        for user in self.networkMap:
            if user[2] == True:
                rule = iptc.Rule()
                rule.in_interface = self.networkInterface
                            
                match = iptc.Match(rule, "mac")
                match.mac_source = user[0].encode('utf8')                       
                
                rule.add_match(match)
                rule.target = iptc.Target(rule, "ACCEPT")
                                
                inputChain.insert_rule(rule)
                            
                rule = iptc.Rule()
                rule.in_interface = self.networkInterface
                            
                match = iptc.Match(rule, "mac")
                match.mac_source = user[0].encode('utf8')                       
                
                rule.add_match(match)
                rule.target = iptc.Target(rule, "ACCEPT")
                                
                forwardChain.insert_rule(rule)

    def printChain(self):
        for chain in iptc.easy.dump_chain('filter', 'INPUT'):
            print(chain)

        print("")
                            
        for chain in iptc.easy.dump_chain('filter', 'FORWARD'):
            print(chain)

        time.sleep(3)

    def run(self):
        rule = iptc.Rule()
        rule.in_interface = self.networkInterface

        inputChain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        forwardChain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "FORWARD")
        
        self.resetChain(inputChain, forwardChain)
        
        self.setDrop(inputChain, forwardChain)
        
        while True:
            time.sleep(10) # BlockChain Request delay

            tempMap = []

            for obj in self.getNetworkMap()['objects']:
                tempMap.append([obj['macAddress'], obj['policyId'], False])

            self.getPermission(tempMap)
                        
            if tempMap != self.networkMap:
                self.networkMap = tempMap

                self.resetChain(inputChain, forwardChain)

                self.setDrop(inputChain, forwardChain)

                self.setAccept(inputChain, forwardChain)

            self.printChain()

if __name__ == '__main__':
    if len(sys.argv) < 4:
        sys.exit("[!] Usage >>> python IoTGateway.py [Network Interface] [Web Server Address] [Web Port]")

    try:
        os.system("systemctl restart hostapd")
        os.system("systemctl restart dnsmasq")

        macAddr = netifaces.ifaddresses(sys.argv[1])[netifaces.AF_LINK][0]['addr'].upper()
        
        print("[+] Gateway Mac Address : " + macAddr)

    except:
        os.system("systemctl stop hostapd")
        os.system("systemctl stop dnsmasq")
        sys.exit("[!] Incorrect network interface name")

    gateway = IoTGateway(sys.argv[1], sys.argv[2], macAddr, sys.argv[3])

    gateway.run()
