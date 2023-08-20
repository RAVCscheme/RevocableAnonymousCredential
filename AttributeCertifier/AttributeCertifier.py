from operator import truediv
import jsonpickle
import json
import psycopg2
import datetime
import time
from dotenv import load_dotenv
import argparse
import os
import sys
import pickle
import socket
import threading
from utils import *
from TTP import *
from web3 import Web3

class AttributeCertfier:
    def __init__(self, title,name, req_ip, req_port,open_ip,open_port,dependency, owner_addr, endpoint):
        self.title = title
        self.name = name
        self.req_ip = req_ip
        self.req_port = req_port
        self.open_ip = open_ip
        self.open_port = open_port
        self.dependency = [] if (dependency == None) else dependency
        self.path = create_initial_dir(os.getcwd(), self.title)
        self.connection = None
        self.schema = {}
        self.num_of_attributes = 0
        self.params = []
        self.pk = None
        self.sk = None
        self.prevParams = []
        self.prevPk = []
        self.served_request = []
        self.owner_address = owner_addr
        self.endpoint = endpoint

    def add_attributes(self,attribute_name, encoding_type, visibility):
        self.schema.setdefault(attribute_name, {"type" : encoding_type, "visibility": "public" if(visibility) else "private" })
        self.num_of_attributes+=1
    
    def write_file(self,filename,data):
        dump_data(self.path + filename, data)
        
    def read_file(self,filename,default = None):
        value = load_data(self.path +filename, default)
        return value
    
    def updatePreviousCAInformation(self):
        if self.dependency == None:
            return
        for i in range(len(self.dependency)):
            title = self.dependency[i]
            print("title")
            print(title)
            # params = load_data(os.getcwd() +"/ROOT/CERTIFIER/"+title+"/"+"params.pickle")
            # pk = load_data(os.getcwd() +"/ROOT/CERTIFIER/"+title+"/"+"pk.pickle")
            query = "Select params, pk FROM certifiers WHERE title = {};".format("'" + title+ "'")
            (params, pk) = fetch_data_one(self.connection, query)
            print("params")
            print(pickle.loads(params))
            print(pickle.loads(pk))
            self.prevParams.append(pickle.loads(params))
            self.prevPk.append(pickle.loads(pk))
    
    def register_blockchain(self):
        _, _, _, hs = self.params
        pk = self.pk
        encoded_hs = [(x[0].n, x[1].n) for x in hs]
        encoded_pk = (pk[0].n, pk[1].n)

        w3 = Web3(Web3.HTTPProvider(self.endpoint))
        tf = json.load(open('./Blockchain/build/contracts/Params.json'))
        query = "SELECT address from contracts WHERE name = {};".format("'Params'")
        params_address = fetch_data_one(self.connection, query)
        #print("Params_address")
        params_address = pickle.loads(params_address[0])
        params_address = Web3.toChecksumAddress(params_address)
        params_contract = w3.eth.contract(address = params_address, abi = tf['abi'])
        tx_hash = params_contract.functions.set_ttp_params(self.title, encoded_pk, encoded_hs).transact({'from': self.owner_address})
        w3.eth.waitForTransactionReceipt(tx_hash)
    
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
    def setup_CA(self):
        get_contracts()
        self.connection = self.connect_db()
        key = "msk"
        self.add_attributes(key,"int",False)
        print("The first attribute of " + self.title +" is secret master key (msk)")

        while True:
            checker = input("Do u want to add the private attribute to "+self.title + " : ")
            if checker == "Y" or checker == "y":
                key = input("Enter the name of the attribute : ")
                print(key)
                value = input("Choose the type of the attribute string - 1, number - 2, and datetime - 3 : ")
                
                value = int(value)
                print(value) 
                if(value == 1):
                    value = "str"
                elif(value == 2):
                    value = "int"
                elif(value == 3):
                    value = "date"

                self.add_attributes(key,value,False)
            else:  
                break
        while True:
            checker = input("Do u want to add the public attribute to "+self.title + " : ") 
            if checker == "Y" or checker == "y":
                key = input("Enter the name of the attribute : ")
                value = input("Choose the type of the attribute string - 1, number - 2, and datetime - 3: ")
                value = int(value) 
                if(value == 1):
                    value = "str"
                elif(value == 2):
                    value = "int"
                elif(value == 3):
                    value = "date"
                self.add_attributes(key,value,True)
            else:
                break
        key = "r"
        self.add_attributes(key,"int",False)
        print("The last attribute of " + self.title +" is a blinding factor (r)")

        #self.write_file("/schema.pickle",self.schema)
        self.params = ttp_setup(self.num_of_attributes-1,self.title)
        #json_param = jsonpickle.encode(self.params)
        #self.write_file("/params.pickle",json_param)
        self.pk, self.sk = ttpKeyGen(self.params)
        #json_pk = jsonpickle.encode(self.pk)
        #self.write_file("/pk.pickle",json_pk)
        certifier.register()

        self.updatePreviousCAInformation()
        self.register_blockchain()

    def request_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.req_ip, int(self.req_port)))        
        print (self.name + " binded to %s  for Certificate Requests" %(self.req_port))
        s.listen(10)    
        print (self.name +" is listening for Certificate requests")
        while True:
                c, addr = s.accept()
                requestJSON = c.recv(8192).decode()
                (prevVcerts, attributes, commit, zkpok) = jsonpickle.decode(requestJSON)

                
                for i in range(len(prevVcerts)):
                    print("prevParams")
                    print(self.prevParams)
                    print("prevPk")
                    print(self.prevPk)
                    print(prevVcerts)
                    print()
                    if not VerifyVcerts(self.prevParams[i], self.prevPk[i], prevVcerts[i][1], SHA256(prevVcerts[i][0])):
                        print("Failed Vcert Verification")
                        continue
                attribute = []
                encode_str = []
                for key in self.schema:
                    if(key == "msk" or key =="r"):
                        continue
                    attribute.append(attributes[key])
                    encode_str.append(self.schema[key]["type"])
                encoded_attribute = encode_attributes(attribute, encode_str)
                print("params")
                print(self.params)
                print("prevP")
                print(self.prevParams)
                print("prevVcert")
                print(prevVcerts)
                print("encoded")
                print(encoded_attribute)
                print("commit")
                print(commit)
                print("zkp")
                print(zkpok)

                result  = VerifyZKPoK(self.params, self.prevParams, prevVcerts, encoded_attribute, commit, zkpok)
                if result == False:
                    c.send("Vcert Reqeust Failed".encode())
                    print("Herer")
                else:
                    print("User with ")
                    for key in self.schema:
                        if(key == "msk" or key =="r"):
                            continue
                        print(key, " : ", attributes[key])
                    print("has requested Verifiable Certificate.")
                    checker = "Y"
                    if checker == "Y" or checker == "y":
                        signature = SignCommitment(self.params, self.sk, commit)
                        issueVcert = (commit, signature)
                        issueVcertJSON = jsonpickle.encode(issueVcert)
                        c.send(issueVcertJSON.encode())
                        self.served_request.append((commit, signature, attributes))
                    else:
                        c.send("CA refused to issue the verifiable certificate.".encode())
                c.shutdown(socket.SHUT_RDWR)
                c.close()

    def findUser(served_requests, vcert):
        for request in served_requests:
            commit, signature, attributes = request
            if commit[0].n == vcert[0][0].n and commit[1].n == vcert[0][1].n and signature[0] == vcert[1][0] and signature[1] == vcert[1][1]:
                return attributes
        return None
    
    def opening_request_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.open_ip, int(self.open_port)))        
        print (self.name + " binded to %s for opener requests" %(self.open_port))
        s.listen(10)    
        print (self.name +" is listening for open requests")
        while True:
            try:
                c, addr = s.accept()
                print(addr)
                openJSON = c.recv(8192).decode()
                vcert = jsonpickle.decode(openJSON)
                checker = input("Do you want to disclose user information ? ")
                if checker == "y" or checker == "Y":
                    attributes = self.findUser(self.served_request, vcert)
                else:
                    attributes = None
                attributesJSON = jsonpickle.encode(attributes)
                c.send(attributesJSON.encode())
                c.close()
            except Exception as e:
                print(e)
                s.shutdown(socket.SHUT_RDWR)
                s.close()

    def register(self):
        #RegisterList = load_data(os.getcwd() + "/ROOT/ca_register.pickle")
        json_param = psycopg2.Binary(pickle.dumps(self.params))
        print(json_param)
        json_schema = psycopg2.Binary(pickle.dumps(self.schema))
        print(json_schema)
        json_pk = psycopg2.Binary(pickle.dumps(self.pk))
        print(json_pk)
        register = { "name" : self.name, "title":self.title,"req_ip" : self.req_ip, "req_port":self.req_port, "open_ip" : self.open_ip, "open_port":self.open_port, "dependency": self.dependency,"params": json_param, "pk": json_pk, "schema": json_schema}
        post_data(self.connection, register, "certifiers")
            

    def __str__(self):
        print("Title of Vcert" +self.title)
        print("Name of provider "+self.name)
        print("Attribute Certifier recieving Vcert requests at " + self.req_ip+" port: "+self.req_port)
        print("Attribute Certifier recieving opening requests at " + self.open_ip+" port: "+self.open_port)
        print("Dependency: ",self.dependency)
        return ""

parser = argparse.ArgumentParser(description="Attribute Certifier Creation")
parser.add_argument("--title", type=str, default = None, required = True, help= "This is the title of the Verifiable Certificate.")
parser.add_argument("--name", type=str, default = None, required = True,  help= "The name of provider giving the Verifiable Certificate")
parser.add_argument("--req-ip", type=str, default = '127.0.0.1', required = False,  help= "The ip at which Attribute Certifier is running for Vcert request.")
parser.add_argument("--req-port", type=str, default = None, required = True,  help= "The port on which Attribute Certifier is running for Vcert request.")
parser.add_argument("--open-ip", type=str, default = '127.0.0.1', required = False,  help= "The ip at which Attribute Certifier is running for opener's request.")
parser.add_argument("--open-port", type=str, default = None, required = True,  help= "The port on which Attribute Certifier is running for opener's request.")
parser.add_argument('--dependency', nargs='+', help='The Vcerts on which the current Vcert issuance depends on.', required=False)
parser.add_argument("--address", type=str, default = None, required = True,  help= "The blockchain address on which Protocol Initiator is running")
parser.add_argument("--rpc-endpoint", type=str, default = None, required = True,  help= "The node rpc endpoint through which a user is connected to blockchain network.")
args = parser.parse_args()

certifier = AttributeCertfier(args.title, args.name, args.req_ip,args.req_port,args.open_ip,args.open_port,args.dependency, args.address, args.rpc_endpoint)
# certifier.register()
certifier.setup_CA()

listen_thread = threading.Thread(target = certifier.request_listener)
open_thread = threading.Thread(target = certifier.opening_request_listener)

listen_thread.start()
open_thread.start()