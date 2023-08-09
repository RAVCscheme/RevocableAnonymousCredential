import jsonpickle
from TTP import *
import datetime
import time

import argparse
import os
import sys
import pickle
import socket
import json
from dotenv import load_dotenv
import psycopg2
from web3 import Web3
from utils import *
from crypto import *

connection = connect_db()
def req_vcert():
    vcert_title = input("Enter the Vcert you want to request : ")
    #d = load_data(os.getcwd() +"/ROOT/ca_register.pickle")
    query = "SELECT * from certifiers;"
    d = fetch_data_all(connection, query)
    depen = []
    req_ip = None
    req_port = None
    for i in d:
        if(i[2] == vcert_title):
            depen = [j for j in i[7]]
            req_ip = i[3]
            req_port = i[4]
            break

    if(req_ip == None):
        print("No such CA registered !")
        return

    vcerts = []
    for i in depen:
        if u.vcert_list.get(i) is not None:
            vcerts.append(u.vcert_list[i])
    ans = u.request_vcert(vcert_title,vcerts, req_ip, req_port)
    if ans is None:
        return
    print("vcert recieved ", ans)

def list_vcert():
    l = load_data(os.getcwd()+"/vcerts.pickle")
    if l is None:
        print("No vcerts found!")
        return
    for i in l:
        j = l[i]
        print("Vcert title", j["title"])
        print("attributes ",j["attributes"])
        print("commit ", j["commit"])
        print("signature ", j["signature"])

def req_cred():
    query = "SELECT * from anon_cred;"
    d = fetch_data_all(connection, query)
    #d = load_data(os.getcwd() +"/ROOT/ac_register.pickle")
    if d is None:
        print("No AC's registered. ")
        return
    for i in range(len(d)):
        print("AC NO. :"+ str(i+1))
        print("Name of Anonymous Credential: "+ d[i][2])
        print("Dependency: "+ ", ".join(d[i][5]))
    while True:
        a = int(input("Enter serial no. of AC to request or 0 to exit"))
        if a == 0:
            return
        #k = load_data( os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/"+ d[a-1]["title"]+"/schema.pickle")
        depen = d[a-1][5]
        print(depen)
        print(u.vcert_list)
        title = d[a-1][2]
        vcerts = []
        for i in depen:
            if u.vcert_list.get(i) is None:
                print("Vcert " + i + " not available. Issue the vcert first and then request again !")
                return
            vcerts.append(u.vcert_list.get(i)) 
        credential = u.req_anon_cred(title, vcerts, depen)
        print("recieved credential")
        print(credential)
        break
    
def list_cred():
    d = load_data(os.getcwd() +"/anon_cred.pickle")
    if d is None:
        print("No anonymous credential found!")
        return

    for i in d:
        j = d[i]
        print()
        print("Anon title", j["title"])
        print("attributes ",j["attributes"])
        print("credential ", j["credential"])
        print("kr ", j["kr"])
        print("W ", j["W"])
        print("timestamp ", j["timestamp"])
        print()
def list_all_ca():
    query = "SELECT * from certifiers;"
    d = fetch_data_all(connection, query)
    #d = load_data(os.getcwd() +"/ROOT/ca_register.pickle")
    count = 0
    for i in range(len(d)):
        print("CA NO. :"+ str(i+1))
        print("Name of Vcert: "+ d[i][2])
        print("Dependency: ",d[i][7])
        print("Request IP and port: " + d[i][3] +"   " + d[i][4])
        print("Open IP and port: " + d[i][5] +"   " + d[i][6])
        #print("Path :" +d[i]["path"])
        print("###############################################################################")
        print()
        count+=1
    while True:
        a = int(input("Enter serial no. of CA for more details or 0 to exit: "))
        if a> count:
            print("Inappropriate choice enter again")
            continue
        if a == 0:
            break
        #k = load_data(d[a-1]["path"]+"/schema.pickle")
        k = pickle.loads(d[a-1][10])
        for i in k:
            print("Attribute: "+i)
            print("Type: "+ k[i]["type"])
            print("Visibility: "+ k[i]["visibility"])

def list_all_ac():
    query = "SELECT * from anon_cred;"
    d = fetch_data_all(connection, query)
    #d = load_data(os.getcwd() +"/ROOT/ac_register.pickle")
    if d is None:
        print("No AC's registered. ")
        return
    for i in range(len(d)):
        print("AC NO. :"+ str(i+1))
        print("Name of Anonymous Credential: "+ d[i][2])
        print("Dependency: "+ ", ".join(d[i][5]))
    while True:
        a = int(input("Enter serial no. of CA for more details or 0 to exit"))
        if a == 0:
            break
        k = pickle.loads(d[a-1][6])
        #k = load_data( os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/"+ d[a-1]["title"]+"/schema.pickle")
        for i in k:
            print("Attributes: " + i + " of type "+ k[i]["type"])

def req_service():
    query = "SELECT * from services;"
    d = fetch_data_all(connection, query)
    #d = load_data(os.getcwd() +"/ROOT/service_register.pickle")
    if d is None:
        print("No AC's registered. ")
        return
    for i in range(len(d)):
        print("Service NO.: "+ str(i+1))
        print("Name of Service: "+ d[i][1])
        print("Dependency: "+ d[i][3])
        print("IP address: " + d[i][4] + "   " + d[i][5])
    a = int(input("Enter serial no. of service to request or 0 to exit"))
    if a == 0: 
        return
    anon_title = d[a-1][3]
    if u.anon_cred_list[anon_title] is None:
        print("Issue anonymous credential "+anon_title +" then request")
        return
    ip = d[a-1][4]
    port =d[a-1][5]
    credential = u.anon_cred_list[anon_title]

    u.RequestService(d[a-1][1], ip, port, credential)
    
    
def list_all_service():
    query = "SELECT * from services;"
    d = fetch_data_all(connection, query)
    #d = load_data(os.getcwd() +"/ROOT/service_register.pickle")
    if d is None:
        print("No Services registered. ")
        return
    for i in range(len(d)):
        print("Service NO.: "+ str(i+1))
        print("Name of Service: "+ d[i][1])
        print("Dependency: "+ d[i][3])
        print("IP address: " + d[i][4] + "   " + d[i][5])
    while True:
        a = int(input("Enter serial no. of service for more details or 0 to exit"))
        if a == 0:
            break
        list_of_anon = d[a-1][3].split(",")
        policy = pickle.loads(d[a-1][6])
        print(policy)
        j = 0
        for i in list_of_anon:
            print("Policy for anonymous credential: " + i)
            query = "SELECT * from anon_cred WHERE title = {};".format("'" + i + "'")
            k = pickle.loads(fetch_data_one(connection, query)[0][6])
            #k = load_data( os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/"+i+"/schema.pickle")
            curr= policy[j]
            p = 0
            for i in k:
                if(k[i]["visibility"] == "public"):
                    print("Attribute: "+ i + " should be disclosed")
                    continue    
                if(curr[p] == 0):
                    print("Attribute: "+ i + " should be undislosed")
                else:
                    print("Attribute: "+ i + " should be dislosed")
                p+=1
            j+=1

def update_witness():
    d = load_data(os.getcwd() +"/anon_cred.pickle")
    if d is None:
        print("No anonymous credential found!")
        return

    k = 0
    for i in d:
        j = d[i]
        print()
        print("Sr no. " + str(k+1))
        print("Anon title", j["title"])
        print("attributes ",j["attributes"])
        print("credential ", j["credential"])
        # print("kr ", j["kr"])
        # print("W ", j["W"])
        # print("timestamp ", j["timestamp"])
        print()
        k+=1
    
    a = int(input("Enter serial no. of cred to update witness"))
    name = list(d.keys())[a-1]
    kr = d[name]["kr"]
    W = d[name]["W"]
    timest = d[name]["timestamp"]

    u.update_witness(W, timest)



    
    
def self_revocation():
    d = load_data(os.getcwd() +"/anon_cred.pickle")
    if d is None:
        print("No anonymous credential found!")
        return

    k = 0
    for i in d:
        j = d[i]
        print("Sr no. " + str(k+1))
        print("Anon title", j["title"])
        print()
        k+=1
    a = int(input("Enter serial no. of cred to revoke"))
    name = list(d.keys())[a-1]
    kr = d[name]["kr"]
    W = d[name]["W"]
    comm = d[name]["commit"]
    sig = d[name]["credential"]
    print(name)
    print(kr)
    print(W)
    print(comm)
    print(sig)
    u.self_revoke(name, sig,comm,kr, W)
    

class User:
    def __init__(self, name, address,endpoint):
        self.unique_name = name
        self.block_address = address
        self.rpc_endpoint = endpoint
        #create_initial_dir(os.getcwd()+"/ROOT/USER",self.unique_name)
        self.path = os.getcwd() + "/ROOT/USER/" + self.unique_name +"/"
        self.msk = genRandom()
        self.vcert_list = load_data(os.getcwd() + "/vcerts.pickle")
        if self.vcert_list is None:
            self.vcert_list = {}
        self.anon_cred_list = load_data(os.getcwd()+ "/anon_cred.pickle")
        if self.anon_cred_list is None:
            self.anon_cred_list = {}
        self.connection = connect_db()
        get_contracts()
        self.contracts = self.load_contracts()

        (w3,p,r,i,o2,a,v) = self.contracts
        
    def gethostbytitle(self, title):
        RegisteredList = load_data(os.getcwd() +"/ROOT/ca_register.pickle")
        print(RegisteredList)
        for register in RegisteredList:
            if register["title"] == title:
                return (register["req-ip"], register["req-port"])
        return ('', '')
    
    def title_to_path(self, title):
        path = None
        d = load_data(os.getcwd() +"/ROOT/ca_register.pickle")
        for i in range(len(d)):
            if(d[i]["title"] == title):
                path = d[i]["path"]
                break
        return path

    def self_revoke(self,name, sig, comm, kr, W):
        (w3,p,r,i,o2,a,v) = self.contracts
        a1 = (W[0].n, W[1].n)
        H = (sig[0][0].n,sig[0][1].n)
        S = (sig[1][0].n,sig[1][1].n)
        a.functions.verify_revocation_request(name, kr,a1, H, S, comm).transact({'from':self.block_address,'gas': 100000000})
        revok_status = a.events.revocation_complete().createFilter(fromBlock="0x0", toBlock='latest')
        asd = False
        while True:
            logg = revok_status.get_new_entries()        
            for i in range(len(logg)):
                asd = True
                # recieve s
                s = int(logg[i]["args"]["c"])
                print("revocation complete")
                print(s)
            if asd:
                break
    def downloadPublicInformation(self, title):
        # schema = load_data(path+"/schema.pickle")
        # params = load_data(path+"/params.pickle")
        # params = jsonpickle.decode(params)
        # pk = load_data(path+"/pk.pickle")
        # pk = jsonpickle.decode(pk)
        query  = "SELECT * from certifiers WHERE title = {};".format("'"+title+"'")
        ans = fetch_data_one(self.connection, query)
        schema = pickle.loads(ans[10])
        params = pickle.loads(ans[8])
        pk = pickle.loads(ans[9])

        return (schema,params, pk)
    
    def load_contracts(self):
        # request_address = load_data(os.getcwd()+"/ROOT/request_address.pickle")
        # issue_address = load_data(os.getcwd()+"/ROOT/issue_address.pickle")
        # opening_address = load_data(os.getcwd()+"/ROOT/opening_address.pickle")
        # accumulator_address  = load_data(os.getcwd()+"/ROOT/accumulator_address.pickle")
        # verify_address  = load_data(os.getcwd()+"/ROOT/verify_address.pickle")

        query = "SELECT address from contracts WHERE name = {};".format("'Params'")
        params_address = pickle.loads(fetch_data_one(self.connection, query)[0])
        #params_address = load_data(os.getcwd()+"/ROOT/params_address.pickle")
        query = "SELECT address from contracts WHERE name = {};".format("'Request'")
        request_address = pickle.loads(fetch_data_one(self.connection, query)[0])

        #request_address = load_data(os.getcwd()+"/ROOT/request_address.pickle")
        query = "SELECT address from contracts WHERE name = {};".format("'Issue'")
        issue_address = pickle.loads(fetch_data_one(self.connection, query)[0])

        #issue_address = load_data(os.getcwd()+"/ROOT/issue_address.pickle")
        query = "SELECT address from contracts WHERE name = {};".format("'Open'")
        opening_address = pickle.loads(fetch_data_one(self.connection, query)[0])

        #opening_address = load_data(os.getcwd()+"/ROOT/opening_address.pickle")
        query = "SELECT address from contracts WHERE name = {};".format("'Accu'")
        accumulator_address = pickle.loads(fetch_data_one(self.connection, query)[0])

        query = "SELECT address from contracts WHERE name = {};".format("'Verify'")
        verify_address = pickle.loads(fetch_data_one(self.connection, query)[0])
        
        w3 = Web3(Web3.HTTPProvider(self.rpc_endpoint, request_kwargs = {'timeout' : 300}))
        tf = json.load(open('./Blockchain/build/contracts/Params.json'))
        params_address = Web3.toChecksumAddress(params_address)
        params_contract = w3.eth.contract(address = params_address, abi = tf['abi']) 

        tf = json.load(open('./Blockchain/build/contracts/Request.json'))
        request_address = Web3.toChecksumAddress(request_address)
        request_contract = w3.eth.contract(address = request_address, abi = tf['abi'])

        tf = json.load(open('./Blockchain/build/contracts/Issue.json'))
        issue_address = Web3.toChecksumAddress(issue_address)
        issue_contract = w3.eth.contract(address = issue_address, abi = tf['abi'])

        tf = json.load(open('./Blockchain/build/contracts/Opening.json'))
        opening_address = Web3.toChecksumAddress(opening_address)
        opening_contract = w3.eth.contract(address = opening_address, abi = tf['abi'])
        
        tf = json.load(open('./Blockchain/build/contracts/Accumulator.json'))
        accumulator_address = Web3.toChecksumAddress(accumulator_address)
        acc_contract = w3.eth.contract(address = accumulator_address, abi = tf['abi'])

        tf = json.load(open('./Blockchain/build/contracts/Verify.json'))
        verify_address = Web3.toChecksumAddress(verify_address)
        verify_contract = w3.eth.contract(address = verify_address, abi = tf['abi'])

        return (w3,params_contract, request_contract, issue_contract, opening_contract, acc_contract, verify_contract)

    def updateRequiredVcerts(self,requiredVcerts):
        prevParams, prevVcerts, prevAttributes = [], [], []
        for i in range(len(requiredVcerts)):
            print("This is the required vcerdts")
            print(requiredVcerts[i])
            title = requiredVcerts[i]["title"]
            # path = self.title_to_path(title)
            schema, params, pk = self.downloadPublicInformation(title)
            prevParams.append(params)
            prevVcerts.append((requiredVcerts[i]["commit"], requiredVcerts[i]["signature"]))
            attributes = []
            encode_str = []
            for key in schema:
                attributes.append(requiredVcerts[i]["attributes"][key])
                encode_str.append(schema[key]["type"])
            prevAttributes.append(encode_attributes(attributes, encode_str))
        return (prevParams, prevVcerts, prevAttributes)

    def connect_to_CA(self, ip, port):
        if port == '':
            print("vcert request failed, no such vcert found")
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as err:
            print ("socket creation failed with error %s" %(err))
        s.connect((ip, int(port)))
        print("connected to port : ", port)
        return s
    
    def request_vcert(self,title,required_vcert, ip ,port):
        s = self.connect_to_CA(ip, port)
        if s is None:
            return
        vcert = {"title":title, "attributes" : None, "commit": None, "signature": None}
        print("Coming to try block")
        prevParams, prevVcerts, prevAttributes = self.updateRequiredVcerts(required_vcert)
        schema, params, pk = self.downloadPublicInformation(title)
        attributes = {}

        val_of_attr = []
        encode_val_of_attr = []
        for key in schema:
                value = None
                if key == "msk":
                    value = self.msk
                    val_of_attr.append(self.msk)
                    encode_val_of_attr.append("int")
                elif key == "r":
                    value = genRandom()
                    val_of_attr.append(value)
                    encode_val_of_attr.append("int")
                elif schema[key]["type"] == "str":
                    value = input("Enter the attribute \'"+key+"\' of type "+schema[key]["type"]+" : ")
                    val_of_attr.append(value)
                    encode_val_of_attr.append("str")
                elif schema[key]["type"] == "int":
                    value = int(input("Enter the attribute \'"+key+"\' of type "+schema[key]["type"]+" : "))
                    val_of_attr.append(value)
                    encode_val_of_attr.append("int")
                elif schema[key]["type"] == "date":
                    str_date = input("Enter the attribute \'"+key+"\' in Y-m-d format : ")
                    _date = datetime.datetime.strptime(str_date,"%Y-%m-%d").date()
                    value = int(_date.strftime('%Y%m%d'))
                    val_of_attr.append(value)
                    encode_val_of_attr.append("date")
                #if(key !="msk" or key != "r"):
                attributes.setdefault(key, value)

        encoded_attribute = encode_attributes(val_of_attr, encode_val_of_attr)
        commit = GenCommitment(params, encoded_attribute)

        prevAttributes.append([self.msk,val_of_attr[-1]])
        print(prevAttributes)
        zkpok = GenZKPoK(params, prevParams, prevVcerts, prevAttributes, commit)
        print(prevVcerts)
        requestJSON = jsonpickle.encode((prevVcerts, attributes, commit, zkpok))
        s.send(requestJSON.encode())
        print("requestjson")
        print(requestJSON)
        issueVcertJSON = s.recv(8192).decode()
        print(issueVcertJSON)
        issueVcert = jsonpickle.decode(issueVcertJSON)
        _commit, signature = issueVcert
        print("This is commit")
        print(_commit)
        if commit != _commit: 
                print("Request is corrupted.")
        elif VerifyVcerts(params, pk, signature, SHA256(commit)) == True:
                vcert["attributes"] = attributes
                vcert["commit"] = commit
                vcert["signature"] = signature
                self.vcert_list[title] = vcert
                print("Vcert recieved sucessfully !")
                dump_data(os.getcwd()+"/vcerts.pickle", self.vcert_list)
        else:
                print("Request is corrupted.")
        s.close()
        return vcert
    

    def getIncludeIndexes(self, title, dependency, p):
        # path = os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/"+title+"/"
        # include_indexes = load_data(path+"/include_indexes.pickle")
        include_indexes = pickle.loads(p[7])
        _include_indexes = []
        for key in dependency:
            _include_indexes.append(include_indexes[key])
        return _include_indexes

    def getAttributes(self,title, vcerts, combination, public_m, schema, p):
        attributes = {}
        for key in schema:
            attributes.setdefault(key, None)
        
        include_indexes = self.getIncludeIndexes(title, combination, p)
        #include_indexes = pickle.loads(p[7])
        for i in range(len(combination)):
            CASchemaOrder,_,_ = self.downloadPublicInformation(combination[i])
            CASchemaOrder = list(CASchemaOrder)
            print(CASchemaOrder)
            for j in range(len(include_indexes[i])):
                if include_indexes[i][j] == 1:
                    attributes[CASchemaOrder[j]] = vcerts[i]["attributes"][CASchemaOrder[j]]
        i = 0
        for key in schema:
            if schema[key]['visibility'] == 'public':
                attributes[key] = public_m[i]
                i += 1
        return attributes

    def req_anon_cred(self, title, vcerts, dependency):
        #when finding vcerts append it's CA as dependency
        #assert checkCombinations(title, combination), "No such combination."
        query="SELECT * FROM anon_cred WHERE title = {};".format("'"+title+"'")
        p = fetch_data_one(self.connection,query)
        #params = setup(load_data(os.getcwd()+"/ROOT/ANONYMOUS_CREDENTIALS/"+title+"/q.pickle"), title)
        params = setup(p[8],title)
        print("this is params")
        print(params)
        #aggr_vk = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/" + title+"/aggregate_vk.pickle")
        aggr_vk = pickle.loads(p[16])
        #encoded_aggregate_vk = jsonpickle.decode(aggr_vk)
        aggr_vk = decodeVk(aggr_vk)
        # to = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/" + title+"/to.pickle")
        # no = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/" + title+"/no.pickle")
        # opks = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/" + title+"/opk.pickle")
        to = p[9][3]
        no = p[9][1]
        opks = pickle.loads(p[13])
        #encoded_opks = jsonpickle.decode(opks)
        opks = decodeToG2List(opks)
        prevVcerts = []
        prevParams = []
        all_encoded_attr = []
        public_m = []
        for cert in vcerts:
            schema, ca_params, _ = self.downloadPublicInformation(cert["title"])
            prevParams.append(ca_params)
            prevVcerts.append((cert["commit"], cert["signature"]))
            attributes = cert["attributes"]
            attribute = []
            encode_str = []
            for key in schema:
                attribute.append(attributes[key])
                encode_str.append(schema[key]["type"])
            encoded_attribute = encode_attributes(attribute, encode_str)
            all_encoded_attr.append(encoded_attribute)
            
        include_indexes = self.getIncludeIndexes(title, dependency, p)
        #include_indexes = pickle.loads(p[7])
        print(include_indexes)
        st = time.time()
        Lambda, oss = PrepareCredRequest(params, aggr_vk, to, no, opks, prevParams, all_encoded_attr, include_indexes, public_m)
        et = time.time()
        print("PrepareCredRequest", et-st)
        (cm, commitments, pi_s, hp, C, pi_o, Dw, Ew, hr, bo) = Lambda
        #anything with "send" appended is making that particular variable as SC compatible.
        co = [add(commitments[i], neg(multiply(G1, oss[i]))) for i in range(len(commitments))]
        send_cm = (cm[0].n, cm[1].n)
        send_commitments = [(commitments[i][0].n, commitments[i][1].n) for i in range(len(commitments))]
        commm = [(co[i][0].n, co[i][1].n) for i in range(len(co))]
        send_ciphershares= [([([C[i][j][0].coeffs[1].n,C[i][j][0].coeffs[0].n],[C[i][j][1].coeffs[1].n, C[i][j][1].coeffs[0].n]) for j in range(2)],) for i in range(len(C))]
        send_compressed_cipher = (send_commitments, send_ciphershares)
        private_m = []
        schema = pickle.loads(p[6])
        #schema = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/"+title+ "/schema.pickle")
        public_m = [] #change this to current public_m value
        attributes = self.getAttributes(title, vcerts, dependency, public_m, schema, p)
        credential = {"title": title, "attributes" : attributes, "credential": None, "kr":None, "W":None, "timestamp": None}
        for key in schema:
            if schema[key]['visibility'] == 'private':
                private_m.append(credential["attributes"][key])
        send_hp =  [[(hp[i][j-1][0].n, hp[i][j-1][1].n) for j in range(1, to)] for i in range(len(private_m))]
        send_hr = [(hr[i][0].n, hr[i][1].n) for i in range(len(hr))]
        send_bo = [([bo[i][0].coeffs[1].n,bo[i][0].coeffs[0].n],[bo[i][1].coeffs[1].n,bo[i][1].coeffs[0].n]) for i in range(len(bo))]
        send_Dw = [([Dw[i][0].coeffs[1].n,Dw[i][0].coeffs[0].n],[Dw[i][1].coeffs[1].n,Dw[i][1].coeffs[0].n]) for i in range(len(Dw))]
        send_Ew = [([Ew[i][0].coeffs[1].n,Ew[i][0].coeffs[0].n],[Ew[i][1].coeffs[1].n,Ew[i][1].coeffs[0].n]) for i in range(len(Ew))]
        send_compressed_G2Points = (send_Dw, send_Ew)
        send_vcerts = [((prevVcerts[i][0][0].n, prevVcerts[i][0][1].n), prevVcerts[i][1]) for i in range(len(prevVcerts))]
        
        (w3,par,r,i,o2,a,v) = self.contracts
        pi_s = list(pi_s)
        pi_s.append(dependency)
        pi_s = tuple(pi_s)
        print("sending for verification")
        str_public_m = [str(public_m[i]) for i in range(len(public_m))]
        #only place where request smart contract is called from User
        st = time.time()
        tx_hash = r.functions.RequestCred(title, send_vcerts, send_cm, send_compressed_cipher, send_hp, send_hr, send_bo, pi_s, pi_o, send_compressed_G2Points, str_public_m).transact({'from':self.block_address})
        et = time.time()
        print("Time for Verification at Smart Contract is:",et-st)
        nv = p[9][0]
        #nv = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/"+title+ "/nv.pickle")
        signs = [None] * nv
        self.ReceivePartialCredentials(title,params, signs, oss, p)
        tx_hash = i.functions.get_kr_W(title).transact({'from':self.block_address})
        acc_filter = a.events.send_W_kr.createFilter(fromBlock="0x0", toBlock='latest')
        asd = False
        kr = None
        W = None
        timestamp_W = None
        end2 = None
        while True:
            storage = acc_filter.get_new_entries()
            for index in range(len(storage)):
                end2 = time.time()
                id = storage[index]['args']["request_id"]
                kr = storage[index]['args']["kr"]
                W =  storage[index]["args"]["W"]
                W = ((FQ(W[0]),FQ(W[1])))
                timestamp_W = int(storage[index]["args"]["timestamp"])
                print("id")
                print(id)
                print("kr")
                print(kr)
                print("W")
                print(W)
                asd =True
            if asd:
                break
        #print("Entire Pcred receiving time is (includes Params SC):",(end-start)+(end2-start2))
        print("kr")
        print(kr)
        st = time.time()
        aggr_sig = AggCred(params, signs)
        et = time.time()
        print("Aggregate", et-st)
        print("Aggregated credential")
        print(aggr_sig)
        credential["credential"] = aggr_sig
        credential["kr"] = kr
        credential["W"] = W
        credential["timestamp"] = timestamp_W
        credential["commit"] = commm
        self.anon_cred_list[title] = credential
        print("anon_cred_list")
        print(self.anon_cred_list)
        print("credential")
        print(credential)
        dump_data(os.getcwd() + "/anon_cred.pickle", self.anon_cred_list)
        gb = time.time()
        #print("CredentialIssuance time", gb-fi)
        
        return credential
    
    def ReceivePartialCredentials(self,title,params, signs, oss, p):
        
        (w3,par,r,i,o2,a,v) = self.contracts
        issue_filter = i.events.emitIssue.createFilter(fromBlock="0x0", toBlock='latest')
        credential_id = par.functions.getMapCredentials(title).call()
        assert credential_id != 0, "No such AC."
        nv = p[9][0]
        #nv = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/"+title+ "/nv.pickle")
        valid = pickle.loads(p[18])
        #valid = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/"+title+ "/validatorsList.pickle")
        validator_dict = {}
        verif_key = pickle.loads(p[12])
        #verif_key = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/"+title+ "/vk.pickle")
        # verif_key = jsonpickle.decode(verif_key)
        verif_key = decodeVkList(verif_key)
        i = 1
        for validator in valid:
            validator_dict.setdefault(validator, i)
            i+=1
        signs_count = 0
        while True:
            signature_log = issue_filter.get_new_entries()
            for k in range(len(signature_log)):
                _credential_id = signature_log[k]['args']['id']
                if credential_id != _credential_id:
                    continue
                receiver = signature_log[k]['args']['receiver']
                if receiver != self.block_address:
                    continue
                issuer_address = signature_log[k]['args']['issuer_address']
                _h = signature_log[k]['args']['h']
                _t = signature_log[k]['args']['t']
                h = (FQ(_h[0]), FQ(_h[1]))
                t = (FQ(_t[0]), FQ(_t[1]))
                blind_sig = (h, t)
                issuer_id = int(validator_dict[issuer_address])
                vk = verif_key[issuer_id-1]
            
                if signs[issuer_id-1] is None:
                    st = time.time()
                    signs[issuer_id-1] = Unblind(params, vk, blind_sig, oss)
                    et = time.time()
                    print("Unblind", et-st)
                    print("Unblind")
                    print(issuer_id)
                    print(signs[issuer_id - 1])
                    signs_count += 1
            if signs_count >= nv:
                break
    
    def RequestService(self, name_of_service, ip, port, credential):
        
        title = credential["title"]
        kr = credential["kr"]
        print("service kr")
        print(kr)
        W = credential["W"]
        print("W")
        print(W)
        print("The available policies are : ")
        (w3,par,r,i,o2,a,v) = self.contracts
        total_policies = v.functions.gettotalPolicies(title).call()
        for i in range(total_policies):
            policy = v.functions.getPolicy(title, i+1).call()
            print("choose "+str(i+1)+" for : ", str(policy))
        policy_id = int(input("Choose any policy : "))
        disclose_index = v.functions.getPolicy(title, policy_id).call()
        ac_encode_str = []
        private_m = []
        query="SELECT * FROM anon_cred WHERE title = {};".format("'"+title+"'")
        p = fetch_data_one(self.connection,query)
        #schema = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/"+title+ "/schema.pickle")
        schema = pickle.loads(p[6])
        for key in schema:
            if schema[key]['visibility'] == 'private':
                private_m.append(credential["attributes"][key])
                ac_encode_str.append(schema[key]["type"])
        disclose_attr = [private_m[i] for i in range(len(private_m)) if disclose_index[i]==1]
        str_disclose_attr = [str(disclose_attr[i]) for i in range(len(disclose_attr))]
        
        #params = setup(load_data(os.getcwd()+"/ROOT/ANONYMOUS_CREDENTIALS/"+title+"/q.pickle"), title)
        params = jsonpickle.decode(pickle.loads(p[10]))
        _, o, _, _, _, _ = params
        encoded_private_m = encode_attributes(private_m, ac_encode_str)
        encoded_disclose_attr = [encoded_private_m[i] for i in range(len(encoded_private_m)) if disclose_index[i]==1]
        disclose_attr_enc = [ac_encode_str[i] for i in range(len(ac_encode_str)) if disclose_index[i]==1]
        public_m = []
        public_m_encoding = []
        for key in schema:
            if schema[key]['visibility'] == 'public':
                public_m.append(credential["attributes"][key])
                public_m_encoding.append(schema[key]["type"])
        encoded_public_m = []
        for i in range(len(public_m)):
            if public_m_encoding[i] == 1:
                encoded_public_m.append(int.from_bytes(sha256(public_m[i].encode("utf8").strip()).digest(), "big") % o)
            else:
                encoded_public_m.append(public_m[i])
        
        #path = os.getcwd()+"/ROOT/ANONYMOUS_CREDENTIALS/"+title
        aggr_vk = pickle.loads(p[16])
        #aggr_vk = load_data(path+"/aggregate_vk.pickle")
        #encoded_aggregate_vk = jsonpickle.decode(aggr_vk)
        aggr_vk = decodeVk(aggr_vk)
        aggr_accum = pickle.loads(p[17])
        #aggr_accum = load_data(path+"/aggregate_vk_a.pickle")
        #aggr_accum = jsonpickle.decode(aggr_accum)
        aggr_accum = decodeToG2(aggr_accum)
        public_params = pickle.loads(p[11])
        #public_params = load_data(path+"/public_params.pickle")
        public_params = jsonpickle.decode(public_params)
        public_params = [(FQ(public_params[0][0]), FQ(public_params[0][1])), decodeToG2(public_params[1]), (FQ(public_params[2][0]), FQ(public_params[2][1])), decodeToG2(public_params[3])] 
	    # proving the possession of AC (Off-chain by user) private_m, disclose_index, disclose_attr, disclose_attr_enc, public_m
        st = time.time()
        pi_c, Theta, aggr = ProveCred(params, aggr_vk, credential["credential"], encoded_private_m, disclose_index, disclose_attr, disclose_attr_enc, encoded_public_m,aggr_accum, public_params,kr, W)
        et = time.time()
        print("Credential proof", et-st)
        (kappa, nu, rand_sig, proof, Aw, _timestamp) = Theta
        (commit, pie_I_1, pie_I_2, R1, R2, R3, s_r,s_tau_1, s_tau_2, s_delta_1, s_delta_2) = pi_c
        send_commit = encodeG2(commit)
        send_pi_I_1 = (pie_I_1[0].n, pie_I_1[1].n)
        send_pi_I_2 = (pie_I_2[0].n, pie_I_2[1].n)
        send_R1 = (R1[0].n, R1[1].n)
        send_R2 = (R2[0].n, R2[1].n)
        send_R3 = encodeGT(R3)
        send_kappa = ((kappa[0].coeffs[1].n, kappa[0].coeffs[0].n), (kappa[1].coeffs[1].n, kappa[1].coeffs[0].n))
        send_nu = (nu[0].n, nu[1].n)
        send_sigma = [(rand_sig[i][0].n, rand_sig[i][1].n) for i in range(len(rand_sig))]
        send_Aw =  ((Aw[0].coeffs[1].n, Aw[0].coeffs[0].n), (Aw[1].coeffs[1].n, Aw[1].coeffs[0].n))
        send_theta = (send_kappa, send_nu, send_sigma, proof, send_Aw, _timestamp)
        send_pi_c = (send_commit, send_pi_I_1, send_pi_I_2, send_R1, send_R2, send_R3, s_r, s_tau_1, s_tau_2, s_delta_1, s_delta_2)
        print("commit")
        print(send_commit)
        print("R1")
        print(send_R1)
        print("R2")
        print(send_R2)
        print("R3")
        print(send_R3)
        if aggr:
            send_aggr = ((aggr[0].coeffs[1].n, aggr[0].coeffs[0].n), (aggr[1].coeffs[1].n, aggr[1].coeffs[0].n))
        else:
            send_aggr = ((0, 0), (0, 0))
        encoded_disclosed_attr = encode_attributes(disclose_attr, disclose_attr_enc)
        #Sending to SP_verify for verifying the proof.
        title=credential["title"]
        self.send_to_SP(ip, port, title,disclose_index,send_theta,encoded_disclosed_attr,encoded_public_m, send_pi_c)

    def send_to_SP(self,ip, port, a,c,d,e,f, g):
        #ip, port = "127.0.0.1", "9000"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print ("Socket successfully created")
        except socket.error as err:
            print ("socket creation failed with error %s" %(err))
        s.connect((ip, int(port)))
        print("connected to port : ", port)
        try:
            validator = {"title": a,"disclose_index":c,"theta": d, "enc_disc_attr": e,"enc_public_m": f, "pi_c": g}
            validator = jsonpickle.encode(validator)
            print("validator")
            print(validator)
            s.send(validator.encode())
            response = s.recv(8192).decode()
            print("Response: " + str(response))
        except Exception as e:
            s.shutdown(socket.SHUT_RDWR)
            print(e)
        finally:
            s.close()
    
    def update_witness(self,witness, timestamp):
        (w3,par,r,i,o2,a,v) = self.contracts
        lists = a.functions.updateWitness(timestamp).transact({'from':self.block_address,'gas': 100000000})
        print(lists)

        


    def __str__(self):
        print("Name of user "+ self.unique_name)
        print("Blockchain address "+ self.block_address)
        print("Vcert list ",self.vcert_list)
        return ""


parser = argparse.ArgumentParser(description="User Creation")
parser.add_argument("--unique-name", type=str, required = True, help= "A name that uniquely identifies the user.")
parser.add_argument("--address", type=str, default = None, required = True,  help= "The blockchain address on which user is running.")
parser.add_argument("--rpc-endpoint", type=str, default = None, required = True,  help= "The node rpc endpoint through which a user is connected to blockchain network.")
args = parser.parse_args()

u = User(args.unique_name,args.address, args.rpc_endpoint)

while True:
    print("1. Request VCerts")
    print("2. List Vcerts")
    print("3. Request Credential")
    print("4. List Credential")
    print("5. Request Service")
    print("6. List Services")
    print("7. List all available CA's")
    print("8. List all available Anonymous credentials")
    print("9. Update Witness")
    print("10. Self revocation")
    a = int(input("Enter choice: "))

    if(a==1):
        req_vcert()
    elif(a==2):
        list_vcert()
    elif(a==3):
        req_cred()
    elif(a==4):
        list_cred()
    elif(a==5):
        req_service()
    elif(a==6):
        list_all_service()
    elif(a==7):
        list_all_ca()
    elif(a==8):
        list_all_ac()
    elif(a==9):
        update_witness()
    elif(a==10):
        self_revocation()
    else:
        print("Incorrect choice!")