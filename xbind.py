#!/usr/bin/env python
#coding:utf-8


import dns.update
import dns.query
import dns.tsigkeyring


##dtwh.com
##192.192.in-addr.arpa

class xbind(object):
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
            iprecord = self.iprecord(ip)
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
        iprecord = self.iprecord(ip)
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

    def iprecord(self,ip):
        iprecord = '.'.join(ip.split('.')[::-1][0:2])
        return iprecord



class bindlocal(object):
    def zoneparse(self,file):
        with open(file) as zonef:
            pass

    def dbparse(self,file):
        pass

