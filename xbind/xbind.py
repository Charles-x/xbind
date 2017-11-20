#!/usr/bin/env python
#coding:utf-8


import dns.update
import dns.query
import dns.tsigkeyring
import re
import json


##dtwh.com
##192.192.in-addr.arpa

class xbinddns(object):
    def __init__(self,zoneA,zonePTR,dnsserver,tsig_key_name,tsig_key):
        self.dnsserver = dnsserver
        self.zoneA = zoneA
        self.zonePTR = zonePTR
        self.keyring = dns.tsigkeyring.from_text({tsig_key_name: tsig_key})
        self.updateA = dns.update.Update(self.zoneA,keyring=self.keyring)
        self.updatePTR = dns.update.Update(self.zonePTR,keyring=self.keyring)

    def dns_add(self,record,ip,FQDN,TTL):
        if record =='A':
            self.updateA.add(FQDN,TTL,record,ip)
        elif record =='PTR':
            iprecord = xbindtool.ip_antitone(ip)
            self.updatePTR.add(iprecord,TTL,record,FQDN)

    def dns_delete(self):
        pass

    def dns_replace(self):
        pass

    def dns_query(self,ip = None,hostname = None):
        if ip & hostname ==None:
            handler = dns.resolver.query(self.zoneA, 'A')
            print handler

    def dns_commit(self,update):
        response = dns.query.tcp(update, self.dnsserver)
        return response

    def A_PTR_all(self,ip,FQDN,TTL=36500):
        iprecord = xbindtool.ip_antitone(ip)
        if '.'.join(FQDN.split('.')[1:]) == self.zoneA:
            hostname = FQDN.split('.')[0]
            FQDN = FQDN+'.'+self.zoneA+'.'
        else:
            hostname = FQDN.split('.')[0]
            FQDN = FQDN+'.'+self.zoneA+'.'
        self.updateA.add(hostname,TTL,'A',ip)
        self.updatePTR.add(iprecord,TTL,'PTR',FQDN)
        A_response = self.dns_commit(self.updateA)
        PTR_response = self.dns_commit(self.updatePTR)
        print "A####################:\n",A_response ,"\nPTR##################:\n",PTR_response




class xbindlocal:
    @staticmethod
    def zoneparse(file = "/etc/bind/named.conf.local"):
        rzone = re.compile(r'.*zone "(\w*\.\w*|\d{1,3}\.\d{1,3}\.in-addr.arpa)"\s.*?{\s*?type (\w*);\s.*?file "(.*)";\s*?allow-update \{ key(.*); \};\s*?\};',re.M)
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
        keyinfo = xbindlocal.zoneparse()
        k = filter(lambda kall, z=keyname: z == kall[0], keyinfo)
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
    def dataget_all(self,ipdata,FQDNdata,TTL=36500):
        self.TTL = TTL
        #verify data
        self.ip = xbindverify.is_ip(ipdata)
        domainall = xbindverify.is_FQDN(FQDNdata)

        #get info for init

        ##use zonename get tsig_key_name and tsig_key
        self.A_domain = domainall[2] #baidu.com
        self.PTR_domain = xbindtool.ip_PTRname(self.ip)+".in-addr.arpa"
        A_domain_info = xbindtool.choosezone(self.A_domain)
        PTR_domain_info = xbindtool.choosezone(self.PTR_domain)
        A_domain_keyname = A_domain_info[-1]
        PTR_domain_keyname = PTR_domain_info[-1]

        ##user keyname get key
        A_domain_key = xbindtool.choosekey(A_domain_keyname)
        PTR_domain_key = xbindtool.choosekey(PTR_domain_keyname)
        if A_domain_key == PTR_domain_key and A_domain_keyname == PTR_domain_keyname:
            self.tsig_key_name = A_domain_keyname ##########
            self.tsig_key = A_domain_key          ##########
        else:
            #TODO:diff key to use dns
            pass

        ###zoneA data
        self.hostname = domainall[0]
        #ip

        ###zonePRT data
        self.PRTip_d = xbindtool.ip_antitone(self.ip)
        self.PTRdomain_d = self.hostname + domainall[3]


    def init(self,dnsserver = '127.0.0.1'):
        self.dnsserver = dnsserver
        self.zoneA = self.A_domain
        self.zonePTR = self.PTR_domain
        self.keyring = dns.tsigkeyring.from_text({self.tsig_key_name: self.tsig_key})
        self.updateA = dns.update.Update(self.zoneA,keyring=self.keyring)
        self.updatePTR = dns.update.Update(self.zonePTR,keyring=self.keyring)

    def create(self,record):
        if record =='A':
            self.updateA.add(self.hostname,self.TTL,record,self.ip)
        elif record =='PTR':
            self.updatePTR.add(self.PRTip_d,self.TTL,record,self.PTR_domain)
        elif record =="all":
            self.updateA.add(self.hostname, self.TTL, record, self.ip)
            self.updatePTR.add(self.PRTip_d, self.TTL, record, self.PTR_domain)

    def delete(self):
        pass

    def update(self):
        pass

    def read(self,ip = None,hostname = None):
        if ip & hostname ==None:
            handler = dns.resolver.query(self.zoneA, 'A')
            print handler

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

