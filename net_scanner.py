import nmap
from scapy.all import *
from threading import Thread
from pprint import pprint

PORT_SERVICE_DICT = {
    "http" : 80,
    "https" : 443,
    "ftp" : 21,
    "ftps" : 990,
    "pop3" : 110,
    "pop3s" : 995,
    "imap" : 143,
    "imaps" : 993,
    "dns" : 53,
    "smtp" : 25,
    "smtps1" : 465,
    "smtps2" : 587, 
    "telnet" : 23

}

class netscanner(object) :
    def __init__(self) :
        self.scanner = nmap.PortScanner()
        self.target = None
        self.dhcp_ser_inf = None

    def set_target(self, target , mask = None) :
        if mask == None :
            self.target = target
            return

        if mask == "255.0.0.0" :
            self.target = target + "/8"
        elif mask == "255.255.0.0" :
            self.target = target + "/16"
        else :
            self.target = target + "/24"
        
    def send_dhcp_request(self) :
        pprint("sending dhcp request packet")
        randmac = RandMAC()
        ethernet = Ether(dst='ff:ff:ff:ff:ff:ff',src=randmac,type=0x800)
        ip = IP(src ='0.0.0.0',dst='255.255.255.255')
        udp = UDP (sport=68,dport=67)
        bootp = BOOTP(chaddr = randmac , ciaddr = '0.0.0.0',xid =  0x01020304,flags= 1)
        dhcp = DHCP(options=[("message-type","discover"),"end"])
        packet = ethernet / ip / udp / bootp / dhcp
        send(packet)

    # ___________________This code is not mine , it's this guy's https://gist.github.com/joncutrer/862488b349a8faea631f6b521fae6c79 ___________________
    def dhcp_get_option(self, dhcp_options, key) :
        must_decode = ['hostname', 'domain', 'vendor_class_id']
        try:
            for i in dhcp_options:
                if i[0] == key:
                    # If DHCP Server Returned multiple name servers 
                    # return all as comma seperated string.
                    if key == 'name_server' and len(i) > 2:
                        return ",".join(i[1:])
                    # domain and hostname are binary strings,
                    # decode to unicode string before returning
                    elif key in must_decode:
                        return i[1].decode()
                    else: 
                        return i[1]        
        except:
            pass
    #_______________________________________________Finish here________________________________________________________________________________________________

    def get_net_public_informations(self) :
        t = Thread(target = (lambda : sniff(filter="udp and (port 67 or 68)", prn=self.sniff_dhcp, count = 1)))
        t.start()
        while self.dhcp_ser_inf == None :
            self.send_dhcp_request()
        result = self.dhcp_ser_inf
        self.dhcp_ser_inf = None
        return result

    # ___________________This code is not mine , it's this guy's https://gist.github.com/joncutrer/862488b349a8faea631f6b521fae6c79 ___________________
    def sniff_dhcp(self, packet) :
        # Match DHCP offer
        if DHCP in packet and packet[DHCP].options[0][1] == 2:
            subnet_mask = self.dhcp_get_option(packet[DHCP].options, 'subnet_mask')
            router = self.dhcp_get_option(packet[DHCP].options, 'router')
            name_server = self.dhcp_get_option(packet[DHCP].options, 'name_server')

            self.dhcp_ser_inf =  {"server_address" : packet[IP].src , "server_name" : name_server , "gateway" : router, "subnet_mask" : subnet_mask}

        # Match DHCP ack
        elif DHCP in packet and packet[DHCP].options[0][1] == 5:
            subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
            router = get_option(packet[DHCP].options, 'router')
            name_server = get_option(packet[DHCP].options, 'name_server')

            self.dhcp_ser_inf = {"server_address" : packet[IP].src , "server_name" : name_server, "gateway" : router , "subnet_mask" : subnet_mask}
        else:
            pprint("some other dhcp packets")
            self.dhcp_ser_inf = None
    
    #_____________________________________________________________Finish here______________________________________________________________________
 
    def find_devices(self, fast = True): 
        if fast :
            scan_type="-sn -T5 --min-parallelism 100"
        else :
            scan_type="-sT"

        scan_result = self.scanner.scan(hosts = self.target, arguments = scan_type)["scan"]
        result = []
        for key in scan_result.keys() :
            result.append({
            "ip" : key,
            "state" : scan_result[key]["status"]["state"],
            "device" : scan_result[key]["vendor"]
            })

        return result
        
    def scan_multi_host(self, hosts, fast=True) :
        if fast :
            scan_type="-sS -sV -T5 --min-parallelism 100"
        else :
            scan_type="-sT -sV"

        shosts = " ".join(hosts)
        scan_result = self.scanner.scan(hosts = shosts, arguments = scan_type)["scan"]
        pprint(scan_result)
        result = {}
        for key in scan_result.keys() :
            rows = {}
            for k in scan_result[key]["tcp"].keys() :
                if scan_result[key]["tcp"][k]["state"] == "open" :
                    rows[k] = scan_result[key]["tcp"][k]
            result[key] = rows

        return result

    def get_open_ports(self) :
        scan_result = self.scanner.scan(hosts=self.target, arguments="-sT -sV" )["scan"]

        # Let's filter them
        result = []
        for key in scan_result.keys() :
            for k in scan_result[key]["tcp"].keys() :
                if scan_result[key]["tcp"][k]["state"] == "open" :
                    result.append({
                        "address" : key ,
                        "port" : k ,
                        "name" : scan_result[key]["tcp"][k]["name"], 
                        "product" : scan_result[key]["tcp"][k]["product"], 
                        "state" : "open"})
        
        return result


    def do_complete_scan(self) :
        scan_result = self.scanner.scan(hosts=self.target, arguments="-p- -O -sU -sV")
        return scan_result["scan"]
    
    def do_custom_scan(self, ports, os_scan = False, with_service =False) :
        sPorts = []
        for port in ports :
            sPorts.append(str(PORT_SERVICE_DICT[port]))

        sPorts = ",".join(sPorts)

        if os_scan :
            args = "-O -sT"
        else :
            args = "-sT"

        if with_service :
            args += " -sV"
        
        scan_result = self.scanner.scan(hosts=self.target,ports=sPorts, arguments=args)
        return scan_result["scan"]

if __name__ == "__main__":
    s = netscanner()
    s.set_target("192.168.0.0/24")
    pprint(s.find_devices())