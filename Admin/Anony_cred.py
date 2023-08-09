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
from web3 import Web3
from utils import *
from crypto import *
import psycopg2
from dotenv import load_dotenv

#encoding_type_map = {"1": type("string"), "2": type(1), "3": type(datetime.datetime.now())}

class Cred:
    def __init__(self,title, name, ip, port, dependency,rpc_endpoint, org_address, opener, validator):
        self.title = title
        self.name = name
        self.ip = ip
        self.port = port
        self.dependency = dependency
        #self.path = create_initial_dir(os.getcwd()+"/ROOT/ANONYMOUS_CREDENTIALS",self.title)
        #self.ca_path = os.getcwd() + "/ROOT/CERTIFIER/"
        self.rpc_endpoint = rpc_endpoint
        self.params = None
        self.q = 0
        self.org_address = org_address
        self.opener_address = opener
        self.validator_address = validator
        self.connection = None
    
    def connect_db(self):
            load_dotenv()
            db_user = os.environ['db_user']
            db_ip = os.environ['db_host']
            db_database = os.environ['db_database']
            db_port = os.environ['db_port']
            connection = psycopg2.connect(user=db_user,
                                        host=db_ip,
                                        port=db_port,
                                        database=db_database)
            return connection
        
    def init_ac(self, schema,inc_ind, q,nv,no,tv,to,params,pp_params,vk,opk,bpk,vk_a,aggr_vk,aggr_vk_a, valid, opener):
        RegisteredList = load_data(os.getcwd() + "/ROOT/ac_register.pickle")
        y = [nv,no,tv,to]
        print("here")
        print(self.title)
        print()
        print(self.name)
        print()
        print(self.ip)
        print()
        print(self.port)
        print()
        print(self.dependency)
        print()
        print(schema)
        print()
        print(inc_ind)
        print()
        print(q)
        print()
        print(y)
        print("params")
        print(params)
        print()
        print(pp_params)
        print()
        print(vk)
        print()
        print(opk)
        print()
        print(bpk)
        print()
        print(vk_a)
        print()
        print(aggr_vk)
        print()
        print(aggr_vk_a)
        print()
        print(valid)
        print()
        print(opener)
        print()
        enc_schema = psycopg2.Binary(pickle.dumps(schema))
        enc_inc_ind = psycopg2.Binary(pickle.dumps(inc_ind))
        enc_params = psycopg2.Binary(pickle.dumps(params))
        enc_pp_params = psycopg2.Binary(pickle.dumps(pp_params))
        enc_vk = psycopg2.Binary(pickle.dumps(vk))
        enc_opk = psycopg2.Binary(pickle.dumps(opk))
        enc_bpk = psycopg2.Binary(pickle.dumps(bpk))
        enc_vk_a = psycopg2.Binary(pickle.dumps(vk_a))
        enc_aggr_vk = psycopg2.Binary(pickle.dumps(aggr_vk))
        enc_aggr_vk_a = psycopg2.Binary(pickle.dumps(aggr_vk_a))
        enc_valid = psycopg2.Binary(valid)
        enc_open = psycopg2.Binary(opener)
        register = { "title":self.title, "name" : self.name, "ip" : self.ip, "port":self.port, "dependency": self.dependency,
                    "schema": enc_schema, "include_index": enc_inc_ind,"num_of_attri":q, "nv_no_tv_to":y, 
                    "params": enc_params, "pp_params": enc_pp_params, "vk": enc_vk, "opk": enc_opk,
                    "bpk": enc_bpk, "vk_a": enc_vk_a, "aggr_vk": enc_aggr_vk, "aggr_vk_a":enc_aggr_vk_a,
                    "valid_addr": enc_valid, "open_addr": enc_open}
        post_data(self.connection,register, "anon_cred")
        
        # if self.dependency != None:
        #     register = { "title":self.title, "name" : self.name, "ip" : self.ip, "port":self.port, "dependency": self.dependency }
        # RegisteredList.append(register)
        # dump_data(os.getcwd() + "/ROOT/ac_register.pickle", RegisteredList)
    
    def setup_cred(self,nv,no,tv,to):
        self.connection = self.connect_db()
        schema = {}
        include_indexes = {}
        dependency_CA = self.dependency

        for certifier in dependency_CA:
            query = "Select schema FROM certifiers WHERE title = {};".format("'" + certifier+ "'")
            ca_schema = pickle.loads(fetch_data_one(self.connection, query)[0])
            print("schema")
            print(ca_schema)
            ca_indexes = [0]
            for attr in ca_schema:
                if(attr == "msk" or attr == "r"):
                    continue
                value = input("Is the private attribute \'"+attr+ "\' is included in " + self.title +" : ")
                if value == "Y" or value == 'y':
                    schema.setdefault(attr, {"type" : ca_schema[attr]["type"], "visibility": "private"})
                    # print("encoding")
                    # print(encoding)
                    ca_indexes.append(1)
                else:
                    ca_indexes.append(0)
            ca_indexes.append(0)
            include_indexes.setdefault(certifier, ca_indexes)

        while True:
            checker = input("Do u want to add the public attribute to "+self.title + " : ")
            if checker == "Y" or checker == "y":
                key = input("Enter the name of the attribute : ")
                value = input("Choose the type of the attribute string - 1, number - 2, or datetime - 3: ")
                if(value == 1):
                    value = "str"
                elif(value == 2):
                    value = "int"
                elif(value == 3):
                    value = "date"
                schema.setdefault(key, {"type" : value, "visibility": "public"})
            else:
                break
       
        self.q = len(schema)
        print("q")
        print(self.q)
        ans = [self.ip, self.port]
        # dump_data(self.path + "/schema.pickle",schema)
        # dump_data(self.path + "/include_indexes.pickle",include_indexes)
        # dump_data(self.path + "/q.pickle", len(schema))
        # dump_data(self.path + "/anon_cred_ip_port", ans)

        #self.init_nv_no(nv,no,tv,to)
        (w3,p,r,issuer,o2,a) = self.load_contracts()
        self.params = setup(self.q, self.title)

        (sk, vk) = ttp_keygen(self.params, tv, nv)
        aggregate_vk = agg_key(self.params, vk)

        (sk_a, vk_a) = ttp_accumelator_keygen(self.params,to,no)
        aggregate_vk_a = agg_key_accumulator(self.params, vk_a)
        
        encoded_vks = self.encodeVkList(vk)
        encoded_aggregate_vk = self.encodeVk(aggregate_vk)
        
        encoded_vks_a = self.encodeVK_Alist(vk_a)
        encoded_aggregate_vk_a = self.encodeG2(aggregate_vk_a)

        (opks, osks) = opener_keygen(self.params, no)
        (bpk, bsk) = gen_beaver_keys(self.params,no)
        for i in opks:
            print("this is opks")
            print(i)
        encoded_opk = self.encodeVK_Alist(opks)
        encoded_bpk = [(bpk[i][0].n, bpk[i][1].n) for i in range(len(bpk))]
        h = multiply(G1,genRandom())
        public_params = [(G1[0].n,G1[1].n),self.encodeG2(G2),(h[0].n, h[1].n), self.encodeG2(multiply(G2, genRandom()))]

        
        json_vk = jsonpickle.encode(encoded_vks)
        #dump_data(self.path +"/vk.pickle",json_vk)
        json_opk = jsonpickle.encode(encoded_opk)
        #dump_data(self.path +"/opk.pickle",json_opk)
        json_bpk = jsonpickle.encode(encoded_bpk)
        #dump_data(self.path +"/bpk.pickle",json_opk)
        json_aggregate_vk = jsonpickle.encode(encoded_aggregate_vk)
        #dump_data(self.path +"/aggregate_vk.pickle",json_aggregate_vk)
        json_vk_a = jsonpickle.encode(encoded_vks_a)
        #dump_data(self.path +"/vk_a.pickle",json_vk)
        json_aggregate_vk_a = jsonpickle.encode(encoded_aggregate_vk_a)
        #dump_data(self.path +"/aggregate_vk_a.pickle",json_aggregate_vk)
        l = jsonpickle.encode(public_params)
        #dump_data(self.path +"/public_params.pickle",l)
        enc_par = jsonpickle.encode(self.params)
        #dump_data(self.path+"/params.pickle", enc_par)
        enc_valid = pickle.dumps(self.validator_address)
        open_valid = pickle.dumps(self.opener_address)
        self.init_ac(schema, include_indexes, self.q,nv,no,tv,to,enc_par,l,
                     encoded_vks, encoded_opk, encoded_bpk, encoded_vks_a, encoded_aggregate_vk,
                     encoded_aggregate_vk_a, enc_valid, open_valid)
        _, o, g1, hs, g2, e = self.params 
        encoded_hs = [(hs[i][0].n, hs[i][1].n) for i in range(len(hs))]
        (_, alpha, g1_beta, beta, yvG)= aggregate_vk
        encoded_alpha = ((alpha[0].coeffs[1].n, alpha[0].coeffs[0].n), (alpha[1].coeffs[1].n, alpha[1].coeffs[0].n))
        encoded_beta = [((beta[i][0].coeffs[1].n,beta[i][0].coeffs[0].n),(beta[i][1].coeffs[1].n,beta[i][1].coeffs[0].n)) for i in range(len(beta))]
        encoded_g1_beta = [(g1_beta[i][0].n, g1_beta[i][1].n) for i in range(len(g1_beta))]
        encoded_opk_2 = [[[opks[i][0].coeffs[1].n, opks[i][0].coeffs[0].n],[opks[i][1].coeffs[1].n, opks[i][1].coeffs[0].n]] for i in range(no)]
        encoded_bpk = [(bpk[i][0].n, bpk[i][1].n) for i in range(len(bpk))]


        encoded_include_indexes = []
        for certifier in self.dependency:
            encoded_include_indexes.append(include_indexes[certifier])
        
        public_m_encoding = []
        for key in schema:
            val = 1
            if(schema[key]["type"] == "int"):
                val = 2
            if(schema[key]["type"] == "date"):
                val = 3
            if schema[key]['visibility'] == 'public':
                public_m_encoding.append(val)

        print(self.dependency)
        tx_hash = p.functions.set_params(self.title, encoded_hs, encoded_alpha, encoded_g1_beta, encoded_beta, encoded_opk_2,encoded_bpk, self.dependency, encoded_include_indexes, public_m_encoding).transact({'from': self.org_address})
        w3.eth.waitForTransactionReceipt(tx_hash)
        
        tx_hash = a.functions.set_accumulator(no,to,nv,tv).transact({'from': self.org_address})
        print(tx_hash)
        w3.eth.waitForTransactionReceipt(tx_hash)

        self.send_keys(encoded_vks, encoded_vks_a,encoded_opk,encoded_bpk, bsk, osks,sk,sk_a, nv, no)
    
        opener_addresses = self.opener_address
        validator_addresses = self.validator_address
        for opener_addr in opener_addresses:
            tx_hash = o2.functions.addOpener(opener_addr).transact({'from':self.org_address})
            w3.eth.waitForTransactionReceipt(tx_hash)

        for validator_addr in validator_addresses:
            tx_hash = issuer.functions.addIssuer(validator_addr).transact({'from':self.org_address})
            w3.eth.waitForTransactionReceipt(tx_hash)
    
    def send_keys(self, encoded_vks, encoded_vks_a,encoded_opk,encoded_bpk, bsk,osks, sk,sk_a,nv,no):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.ip, int(self.port)))
        print (self.name + " binded to %s" %(self.port))
        s.listen(10)
        print(self.name +" is listening")
        
        key_request_count = 0
        while key_request_count < nv:
            try:
                c, addr = s.accept()
                validator = c.recv(8192).decode() # validator:1
                v_id = int(validator.split(":")[1])
                keys = (encoded_vks[v_id-1], sk[v_id-1])
                keysJSON = jsonpickle.encode(keys)
                c.send(keysJSON.encode())
                print("sent keys to Validator : ", str(v_id))
                key_request_count += 1
                c.close()
            except Exception as e:
                print(e)
                s.shutdown(socket.SHUT_RDWR)
                s.close()
        
        key_request_count = 0
        while key_request_count < no:
            try:
                c, addr = s.accept()
                opener = c.recv(8192).decode() # validator:1
                o_id = int(opener.split(":")[1])

                keys = (encoded_opk[o_id-1], osks[o_id-1], encoded_vks_a[o_id-1], sk_a[o_id-1], encoded_bpk[o_id-1], bsk[o_id-1])
                print("keys")
                print(keys)
                keysJSON = jsonpickle.encode(keys)
                c.send(keysJSON.encode())
                print("sent keys to Opener : ", str(o_id))
                key_request_count += 1
                c.close()
            except Exception as e:
                print(e)
                s.shutdown(socket.SHUT_RDWR)
                s.close()

    def load_contracts(self):
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

        #accumulator_address  = load_data(os.getcwd()+"/ROOT/accumulator_address.pickle")
        
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

        return (w3,params_contract, request_contract, issue_contract, opening_contract, acc_contract)


    # def init_nv_no(self,nv,no,tv,to):
    #     dump_data(self.path + "/nv.pickle", nv)
    #     dump_data(self.path + "/no.pickle", no)
    #     dump_data(self.path + "/tv.pickle", tv)
    #     dump_data(self.path + "/to.pickle", to)
    #     dump_data(self.path + "/validatorsList.pickle",[])
    #     dump_data(self.path + "/openersList.pickle",[])
    
    def encodeVK_Alist(self,vk):
        vks = []
        for i in vk:
            vks.append(self.encodeG2(i))
        return vks
    
    def encodeG2(self,g2):
        return (g2[0].coeffs[0].n, g2[0].coeffs[1].n, g2[1].coeffs[0].n, g2[1].coeffs[1].n)
    
    def encodeVk(self, vk):
        g2, g2x, g1y, g2y,ycG = vk
        encoded_vk = []
        encoded_vk.append(self.encodeG2(g2))
        encoded_vk.append(self.encodeG2(g2x))
        encoded_vk.append(g1y)
        encoded_g2y = []
        for i in range(len(g2y)):
            encoded_g2y.append(self.encodeG2(g2y[i]))
        encoded_vk.append(encoded_g2y)
        encoded_vk.append(self.encodeG2(ycG))
        return tuple(encoded_vk)
    
    def encodeVkList(self, vks):
        encoded_vks = []
        for vk in vks:
            if vk is not None:
                encoded_vks.append(self.encodeVk(vk))
            else:
                encoded_vks.append(None)
        return encoded_vks

parser = argparse.ArgumentParser(description="Anonymous Credentials registration")
parser.add_argument("--title", type=str, default = None, required = True, help= "This is the title of the Anonymous Credential.")
parser.add_argument("--name", type=str, default = None, required = True,  help= "The name of organisation giving the Anonymous Credential")
parser.add_argument("--ip", type=str, default = '127.0.0.1', required = False,  help= "The ip at which organisation is running.")
parser.add_argument("--port", type=str, default = None, required = True,  help= "The port on which organisation is running.")
parser.add_argument('--dependency', nargs='+', help='The Vcerts on which the Anonymous Credential issuance depends on.', required=False)
parser.add_argument("--address", type=str, default = None, required = True,  help= "The blockchain address on which organization is running.")
parser.add_argument('--validator-addresses', nargs='+', help='The blockchain addresses of the validators for the Anonymous Credential issuance.', required=True)
parser.add_argument('--opener-addresses', nargs='+', help='The blockchain addresses of the openers for the Anonymous Credential opening.', required=True)
parser.add_argument("--rpc-endpoint", type=str, default = None, required = True,  help= "The node rpc endpoint through which a client is connected to blockchain network.")
args = parser.parse_args()

a = Cred(args.title, args.name, args.ip, args.port, args.dependency, args.rpc_endpoint, args.address, args.opener_addresses, args.validator_addresses)     
a.setup_cred(3,3,2,2)
