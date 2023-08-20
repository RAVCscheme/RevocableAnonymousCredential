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


parser = argparse.ArgumentParser(description="Anonymous Credential Law to Opening")
parser.add_argument("--title", type=str, default = None, required = True, help= "This is the title of the Anonymous Credential.")
parser.add_argument("--rpc-endpoint", type=str, default = None, required = True,  help= "The node rpc endpoint through which a opener is connected to blockchain network.")
args = parser.parse_args()


def connect_db():
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
conn = connect_db()


ac_file_path = os.path.join(os.getcwd(), "served_service_requests.pickle")
f = open(ac_file_path,'rb')
service_dict = pickle.load(f)
f.close()

def load_contracts(conn,endpoint):
        # params_address = load_data(os.getcwd()+"/ROOT/params_address.pickle")
        # request_address = load_data(os.getcwd()+"/ROOT/request_address.pickle")
        # issue_address = load_data(os.getcwd()+"/ROOT/issue_address.pickle")
        # opening_address = load_data(os.getcwd()+"/ROOT/opening_address.pickle")
        # accumulator_address  = load_data(os.getcwd()+"/ROOT/accumulator_address.pickle")

        query = "SELECT address from contracts WHERE name = {};".format("'Params'")
        params_address = pickle.loads(fetch_data_one(conn, query)[0])
        #params_address = load_data(os.getcwd()+"/ROOT/params_address.pickle")
        query = "SELECT address from contracts WHERE name = {};".format("'Request'")
        request_address = pickle.loads(fetch_data_one(conn, query)[0])

        #request_address = load_data(os.getcwd()+"/ROOT/request_address.pickle")
        query = "SELECT address from contracts WHERE name = {};".format("'Issue'")
        issue_address = pickle.loads(fetch_data_one(conn, query)[0])

        #issue_address = load_data(os.getcwd()+"/ROOT/issue_address.pickle")
        query = "SELECT address from contracts WHERE name = {};".format("'Open'")
        opening_address = pickle.loads(fetch_data_one(conn, query)[0])

        #opening_address = load_data(os.getcwd()+"/ROOT/opening_address.pickle")
        query = "SELECT address from contracts WHERE name = {};".format("'Accu'")
        accumulator_address = pickle.loads(fetch_data_one(conn, query)[0])

        query = "SELECT address from contracts WHERE name = {};".format("'Verify'")
        verify_address = pickle.loads(fetch_data_one(conn, query)[0])
        
        w3 = Web3(Web3.HTTPProvider(endpoint, request_kwargs = {'timeout' : 300}))
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

# ------------------------------------------------------------------------
(w3, params_contract, _, _,_,_) = load_contracts(conn, args.rpc_endpoint)
credential_id = params_contract.functions.getMapCredentials(args.title).call()
assert credential_id != 0, "No such AC."

print("Select a session to open : ")
for session in service_dict.keys():
	print(session)

session = int(input("Enter session id : "))

open_sigma = service_dict[session][credential_id][0]

# query = "SELECT open_ip, open_port from certifiers;"
# ans = fetch_data_all(conn, query)
# print(ans)
#print(open_sigma)
opener_ip_map_list = [('127.0.0.1', '8001'), ('127.0.0.1', '8002'), ('127.0.0.1', '8003')]

count = 0
for opener_ip_port in opener_ip_map_list:
	# if count == 0:
	# 	count += 1
	# 	continue
	ip, port = opener_ip_port
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, int(port)))
	sigmaJSON = jsonpickle.encode(open_sigma)
	s.send(sigmaJSON.encode())
	s.close()
	count += 1