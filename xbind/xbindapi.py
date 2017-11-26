#!/usr/bin/python
#coding:utf-8

from flask import Flask, jsonify,abort,request
import json
import xbind


##dtwh.com
##192.192.in-addr.arpa

app = Flask(__name__)

@app.route('/dns', methods=['GET','DELETE','POST'])
def get_tasks():
    if request.method == 'GET':
        ip = request.args.get('ip',None)
        FQDN = request.args.get('FQDN',None)
        handler_dns = xbind.xbind()
        data = handler_dns.read(ip,FQDN)
        return data


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
                handler_dns.init()
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
        rdata = request.get_json()
        if rdata != None:
            data = rdata
            ip = data.get("ip", None)
            FQDN = data.get("FQDN", None)
            if ip and FQDN:
                handler_dns = xbind.xbind()
                handler_dns.dataget_all(ip, FQDN)
                handler_dns.init()
                handler_dns.delete("all")
                result = handler_dns.commit("all")
                for i in result:
                    print i
            sdata = {"request": "success", "data": "ok!", "code": "6"}
            return json.dumps(sdata)
        else:
            print "else"
            edata = {"request": "success", "data": "data type error!", "code": "0"}
            return json.dumps(edata)

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
