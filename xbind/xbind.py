#!/usr/bin/env python
#coding:utf-8


import dns.update
import dns.query
import dns.zone
import dns.resolver
import dns.reversename
import dns.tsigkeyring
import re
import json


##dtwh.com
##192.192.in-addr.arpa

class xbindlocal:
    @staticmethod
    def zoneparse(file = "/etc/bind/named.conf.local"):
        rzone = re.compile(r'.*zone "(\w*\.\w*|\d{1,3}\.\d{1,3}\.in-addr.arpa)"\s.*?{\s*?type (\w*);\s.*?file "(.*)";\s*?allow-update \{ key (.*); \};\s*?\};',re.M)
        with open(file,"r") as zonef:
            data = zonef.read()
            zoneinfo = rzone.findall(data)
            #zoneinfo [('dtwh.com', 'master', '/etc/bind/db.dtwh.com', ' key01'), ('192.192.in-addr.arpa', 'master', '/etc/bind/db.192.192', ' key01')]
            return zoneinfo
    @staticmethod
    def keyparse(file = "/etc/bind/tsig.key"):
        rkey = re.compile(r'key "(.*)" \{\s*?algorithm (.*?);\s*?secret "(.*?)";\s*?\};',re.M)
        with open (file,"r") as keyf:
            data = keyf.read()
            keyinfo = rkey.findall(data)
            #keyinfo [('key01', 'hmac-md5', 'OPJEiEP3oqxxnOGCcyezuQ=='), ('key02', 'hmac-md5', 'ZhXmCttHVUVkTSilFTNrkg=='), ('rndc-key', 'hmac-md5', '4tgwAYWm4jFRFgF2BjZE7Q==')]
            return keyinfo
    @staticmethod
    def dbparse(file):
        pass

class xbindtool():
    @staticmethod
    def ip_antitone(ipdata):
        iprecord = '.'.join(ipdata.split('.')[::-1][0:2])
        return iprecord

    @staticmethod
    def ip_PTRname(ipdata):
        return '.'.join(ipdata.split('.')[:2])

    @staticmethod
    def choosezone(zonename):
        zoneinfo = xbindlocal.zoneparse()
        m = filter(lambda zall, z=zonename: z == zall[0], zoneinfo)
        return m

    @staticmethod
    def choosekey(keyname):
        keyinfo = xbindlocal.keyparse()
        k = filter(lambda kall, k=keyname: k == kall[0], keyinfo)
        return k



class xbindverify():
    @staticmethod
    def is_ip(ipdata):
        rip = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        if rip.match(ipdata):
            return ipdata
        else:
            return None

    @staticmethod
    def is_json(jsondata):
        try:
            data = json.loads(jsondata)
        except ValueError:
            return None
        return data

    @staticmethod
    def is_FQDN(FQDNdata):
        rFQDN = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\.?)')
        data = rFQDN.match(FQDNdata)
        if data:
            FQDN = data.group(0)
            hostname = FQDN.split(".")[0]
            domain = '.'.join(FQDN.split(".")[-2:])
            PTRdomain = domain+"."
            return (hostname,FQDN,domain,PTRdomain)
        else:
            return None


class xbind():
    def dataget_all(self,ipdata,FQDNdata,TTL=604800):
        self.TTL = TTL
        #verify data
        self.ip = xbindverify.is_ip(ipdata)
        print "1-----",self.ip
        domainall = xbindverify.is_FQDN(FQDNdata)
        print "2-----",domainall
        #get info for init

        ##use zonename get tsig_key_name and tsig_key
        self.A_domain = domainall[2] #baidu.com
        self.PTR_domain = xbindtool.ip_PTRname(self.ip)+".in-addr.arpa"
        A_domain_info = xbindtool.choosezone(self.A_domain)
        PTR_domain_info = xbindtool.choosezone(self.PTR_domain)

        #get keyring info
        A_domain_keyname = A_domain_info[0][-1]
        PTR_domain_keyname = PTR_domain_info[0][-1]

        ##user keyname get key
        A_domain_key = xbindtool.choosekey(A_domain_keyname)[0][-1]
        PTR_domain_key = xbindtool.choosekey(PTR_domain_keyname)[0][-1]

        self.tsig_key_name_A = A_domain_keyname ##########
        self.tsig_key_A = A_domain_key          ##########
        self.tsig_key_name_PTR = PTR_domain_keyname ##########
        self.tsig_key_PTR = PTR_domain_key          ##########
        ######## make keyring
        self.keyring_A = dns.tsigkeyring.from_text({self.tsig_key_name_A: self.tsig_key_A})
        self.keyring_PTR = dns.tsigkeyring.from_text({self.tsig_key_name_PTR: self.tsig_key_PTR})


        ###zoneA data
        self.hostname = domainall[0]
        #ip

        ###zonePRT data
        self.PRTip_d = xbindtool.ip_antitone(self.ip)
        self.PTRdomain_d = "{}.{}".format(self.hostname,domainall[3])
        print "PTR_domain:    ",self.PTR_domain
        print "PTRdomain_d:    ",self.PTRdomain_d


    def init(self,dnsserver = '127.0.0.1'):
        self.dnsserver = dnsserver
        self.zoneA = self.A_domain
        print "zone A     ",self.zoneA
        self.zonePTR = self.PTR_domain+"."
        print "PTR_domain:   "+self.PTR_domain
        if self.keyring_A != None:
            self.updateA = dns.update.Update(self.zoneA,keyring=self.keyring_A)
        if self.keyring_PTR !=None:
            self.updatePTR = dns.update.Update(self.zonePTR,keyring=self.keyring_PTR)
        print "dnsserver:   "+self.dnsserver
        print "zoneA:   "+self.zoneA
        print "zonePTR:   "+self.zonePTR



    def create(self,record):
        if record =='A':
            self.updateA.add(self.hostname,self.TTL,record,self.ip)
        elif record =='PTR':
            self.updatePTR.add(self.PRTip_d,self.TTL,record,self.PTRdomain_d)
        elif record =="all":
            self.updateA.add(self.hostname, self.TTL, "A", self.ip)
            self.updatePTR.add(self.PRTip_d, self.TTL, "PTR", self.PTRdomain_d)

    def delete(self,record):
        if record =='A':
            self.updateA.delete(self.hostname)
        elif record =='PTR':
            self.updatePTR.delete(self.PRTip_d)
        elif record =="all":
            self.updateA.delete(self.hostname)
            self.updatePTR.delete(self.PRTip_d)

    def update(self):
        pass

    def read(self,ip = None,FQDN = None):
        if ip == None and FQDN == None:
            zones = xbindlocal.zoneparse()
            data = []
            for i in zones:
                data.append(i[0])
            return json.dumps({"data": data})

        elif ip and FQDN != None:
            #TODO:use ip and FQDN to verify the relevance
            pass

        elif ip == None and FQDN != None:
            if FQDN[-1] == ".":
                # show the all record from the domain
                domain = FQDN
                z = dns.zone.from_xfr(dns.query.xfr(self.dnsserver, domain))
                names = z.nodes.keys()
                data = []
                for n in names:
                    FQDNrecord = "{}.{}".format(n, domain)
                    record = z[n].to_text(n).encode("utf-8").split(" ")
                    if len(record) == 5:
                        data.append({"ip": record[-1], "FQDN": FQDNrecord})
                return json.dumps({"data":data})

            else:
                FQDNr = dns.name.from_text(FQDN)
                r = dns.resolver.Resolver()
                r.nameservers = [self.dnsserver]
                query = r.query(FQDNr, "A")
                response = query.response
                data = response.answer[0].to_text().split()[-1]
                return json.dumps({"FQDN": FQDN, "ip": data})


        elif ip !=None and FQDN ==None:
            addr = dns.reversename.from_address(ip)
            r = dns.resolver.Resolver()
            r.nameservers = [self.dnsserver]
            query = r.query(addr, "PTR")
            response = query.response
            data = response.answer[0].to_text().split()[-1]
            name = data[:-1]
            return json.dumps({"FQDN":name,"ip":ip})



    def commit(self,record):
        if record =='A':
            response = dns.query.tcp(self.updateA, self.dnsserver)
            return response
        elif record =='PTR':
            response = dns.query.tcp(self.updatePTR, self.dnsserver)
            return response
        elif record =="all":
            response1 = dns.query.tcp(self.updateA, self.dnsserver)
            response2 = dns.query.tcp(self.updatePTR, self.dnsserver)
            return response1,response2