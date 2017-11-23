#!/usr/bin/python
#coding:utf-8

from flask import Flask, jsonify,abort,request
import json
import xbind


##dtwh.com
##192.192.in-addr.arpa

zoneA = "dtwh.com"
zonePTR = "192.192.in-addr.arpa"
dnsserver = "172.16.137.11"
tsig_key_name = "key01"
tsig_key = "OPJEiEP3oqxxnOGCcyezuQ=="
tsig_algorithm = "hmac-md5"

app = Flask(__name__)

@app.route('/dns', methods=['GET','DELETE','POST'])
def get_tasks():
    handler = xbind.xbinddns(zoneA, zonePTR, dnsserver, tsig_key_name, tsig_key)
    if request.method == 'GET':
        hostname = request.args.get('hostname')
        ip = request.args.get('ip')
        if hostname and ip !=None:
            handler.A_PTR_all(ip,hostname)
        elif hostname != None:
            handler.dns_query(hostname)
        elif ip != None:
            handler.dns_query(ip)
        else:
            handler.dns_query(zoneA)

    elif request.method == 'POST':
        rdata = request.get_json()
        if rdata != None:
            # print json.loads(rdata)
            # data = xbind.xbindverify.is_json(rdata)
            data = rdata
            ip = data.get("ip", None)
            FQDN = data.get("FQDN", None)
            if ip and FQDN:
                handler_dns = xbind.xbind()
                handler_dns.dataget_all(ip,FQDN)
                handler_dns.init(dnsserver="172.16.137.11")
                handler_dns.create("all")
                result = handler_dns.commit("all")
                for i in result:
                    print i
            sdata = {"request": "success", "data": "ok!", "code": "6"}
            return json.dumps(sdata)
        else:
            print "else"
            edata = {"request": "success", "data": "data type error!", "code": "0"}
            return json.dumps(edata)



    elif request.method == 'DELETE':
        print "delete"
        hostname = request.args.get('hostname')
        ip = request.args.get('ip')
        if hostname and ip != None:
            print hostname,ip

    return 'ok'

# class xbinderror:
#     def __init__(self):
#         self.jdata = None
#         self.dataerror = "0"
#
#     def data_error(self,code):
#         if code == 0:
#             self.jdata = {"request":"success","data":"data type error!","code":self.dataerror}
#
#         return self.jdata


if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0',port=53535)
