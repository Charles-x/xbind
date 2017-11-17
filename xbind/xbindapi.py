#!/usr/bin/python
#coding:utf-8

from flask import Flask, jsonify,abort,request
from xbind import xbind


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
    handler = xbind(zoneA, zonePTR, dnsserver, tsig_key_name, tsig_key)
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
        print request.args



    elif request.method == 'DELETE':
        hostname = request.args.get('hostname')
        ip = request.args.get('ip')
        if hostname and ip != None:
            print hostname,ip



    return 'ok'


if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=53535)
