import jsonpickle
import socket
import argparse
from web3 import Web3
import os
import pickle
import json
import threading
from crypto import *
from utils import *

class ServiceProvide:

    def __init__(self, title, name, address, rpc_endpoint, depends, ip ,port):
        self.title = title
        self.name = name
        self.address = address
        #self.vrf_address = verify_address
        self.rpc_endpoint = rpc_endpoint
        self.depends = depends[0]
        self.ip = ip
        self.port = port
        get_contracts()
        self.connection = connect_db()
        #create_initial_dir(os.getcwd()+"/ROOT/SERVICES",self.name)
        #self.path = os.getcwd() + "/ROOT/SERVICES/" + self.name +"/"
        #self.ac_path = os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/"
        self.policy = {}
        self.service_dict = {}
        dump_data(os.getcwd() + "/served_service_requests.pickle", self.service_dict)
        self.contracts = self.load_contracts()
    
    def load_contracts(self):
        # params_address = load_data(os.getcwd()+"/ROOT/params_address.pickle")
        # request_address = load_data(os.getcwd()+"/ROOT/request_address.pickle")
        # issue_address = load_data(os.getcwd()+"/ROOT/issue_address.pickle")
        # verify_address = load_data(os.getcwd()+"/ROOT/verify_address.pickle")
        # accumulator_address  = load_data(os.getcwd()+"/ROOT/accumulator_address.pickle")
        query = "SELECT address from contracts WHERE name = {};".format("'Params'")
        params_address = pickle.loads(fetch_data_one(self.connection, query)[0])

        query = "SELECT address from contracts WHERE name = {};".format("'Request'")
        request_address = pickle.loads(fetch_data_one(self.connection, query)[0])

        query = "SELECT address from contracts WHERE name = {};".format("'Issue'")
        issue_address = pickle.loads(fetch_data_one(self.connection, query)[0])

        query = "SELECT address from contracts WHERE name = {};".format("'Open'")
        opening_address = pickle.loads(fetch_data_one(self.connection, query)[0])

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

        tf = json.load(open('./Blockchain/build/contracts/Verify.json'))
        verify_address = Web3.toChecksumAddress(verify_address)
        verify_contract = w3.eth.contract(address = verify_address, abi = tf['abi'])
        
        tf = json.load(open('./Blockchain/build/contracts/Accumulator.json'))
        accumulator_address = Web3.toChecksumAddress(accumulator_address)
        acc_contract = w3.eth.contract(address = accumulator_address, abi = tf['abi'])

        return (w3,params_contract, request_contract, issue_contract, verify_contract, acc_contract)
    
    def SP_setup(self):
        (w3,params_contract, request_contract, issue_contract, verify_contract, acc_contract) = self.contracts
        print(self.depends)
        query = "SELECT schema from anon_cred WHERE title = {};".format("'" + self.depends+"'")
        g = pickle.loads(fetch_data_one(self.connection, query)[0])
        #g = load_data(self.ac_path + self.depends +"/schema.pickle")
        policy = []
        while True:
            cur_policy = []
            print("Choose the policy for "+ self.depends +" : ")
            for k in g:
                    if g[k]['visibility'] == "private":
                        tmp = input("Do you choose the "+ k +" to be disclosed ? ")
                        if tmp == 'no' or tmp == 'n':
                            cur_policy.append(0)
                        else:
                            cur_policy.append(1)
            policy.append(cur_policy)
            tmp = input("Do you want to another policy ? ")
            if tmp == 'no' or tmp == 'n':
                break
        tx_hash = verify_contract.functions.setPolicy(self.depends, policy).transact({'from':self.address})
        w3.eth.waitForTransactionReceipt(tx_hash)
        self.policy = policy

        d = {"name": self.name, "address": psycopg2.Binary(pickle.dumps(self.address)), "dependency": self.depends, "IP": self.ip, "port": self.port, "policy": psycopg2.Binary(pickle.dumps(self.policy))}
        post_data(self.connection,d,"services")
        # RegisterList = load_data(os.getcwd() + "/ROOT/service_register.pickle")
        # RegisterList.append(d)
        # dump_data(os.getcwd() + "/ROOT/service_register.pickle", RegisterList)
    
    def decodeToG2(self,encoded_g2):
        return (FQ2([encoded_g2[0], encoded_g2[1],]), FQ2([encoded_g2[2], encoded_g2[3],]),)

    def decodeToGT(self,encoded_g2):
        return FQ12([encoded_g2[0], encoded_g2[1],encoded_g2[2],encoded_g2[3],
	       		encoded_g2[4], encoded_g2[5],encoded_g2[6],encoded_g2[7],
				encoded_g2[8], encoded_g2[9],encoded_g2[10],encoded_g2[11]])
    
    def listen_to_requests(self):
        (w3,params_contract, request_contract, issue_contract, verify_contract, acc_contract) = self.contracts
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.ip, int(self.port)))
        print (" binded to %s" %(self.port))
        s.listen(10)
        print (" is listening")
        
        while True:
            c, addr = s.accept()
            ServiceRequest = c.recv(8192).decode()
            ServiceRequest = jsonpickle.decode(ServiceRequest)
            print("ServiceReq")
            print(ServiceRequest)
            title = ServiceRequest["title"]
            disclose_index = ServiceRequest["disclose_index"]
            Theta = ServiceRequest["theta"]
            encoded_disclosed_attr = ServiceRequest["enc_disc_attr"]
            encoded_public_m = ServiceRequest["enc_public_m"]
            print("ServiceReq")
            (kappa, nu, rand_sig, proof, Aw, _timestamp) = Theta
            print("ServiceReq")
            send_kappa = (FQ2([kappa[0][1], kappa[0][0]]), FQ2([kappa[1][1], kappa[1][0]]))
            print("ServiceReq")
            send_nu = (FQ(nu[0]), FQ(nu[1]))
            send_sigma = [(FQ(rand_sig[i][0]), FQ(rand_sig[i][1])) for i in range(len(rand_sig))]
            print("send_sigma")
            print(send_sigma)
            send_theta = (send_kappa, send_nu, send_sigma, proof, Aw, _timestamp)
            print("ServiceReq")
            pi_c = ServiceRequest["pi_c"]
            (commit, pie_I_1, pie_I_2, R1, R2, R3, s_r,s_tau_1, s_tau_2, s_delta_1, s_delta_2) = pi_c
            send_commit = self.decodeToG2(commit)
            send_pi_I_1 = (FQ(pie_I_1[0]), FQ(pie_I_1[1]))
            send_pi_I_2 = (FQ(pie_I_2[0]), FQ(pie_I_2[1]))
            send_R1 = (FQ(R1[0]), FQ(R1[1]))
            send_R2 = (FQ(R2[0]), FQ(R2[1]))
            send_R3 = self.decodeToGT(R3)
            print("send_to_R3")
            print(send_R3)
            send_pi_c = (send_commit, send_pi_I_1, send_pi_I_2, send_R1, send_R2, send_R3, s_r,s_tau_1, s_tau_2, s_delta_1, s_delta_2)
            delta = acc_contract.functions.get_delta().call()
            delta = (FQ(delta[0]), FQ(delta[1]))
            print("delta")
            print(delta)
            t = self.SP_RequestService(title,disclose_index,send_theta,encoded_disclosed_attr,encoded_public_m, send_pi_c, delta)
            print(t)
            id = 1
            if t:
                (kappa, nu, sigma, proof, Aw, _timestamp) = send_theta
                params =(0,0,0,0,0,0)
                h = compute_hash(params, sigma[0])
                service_session_id = int.from_bytes(to_binary256(h), 'big', signed=False)
                self.service_dict.setdefault(service_session_id, {})
                print("sigma")
                print(sigma)
                self.service_dict[service_session_id].setdefault(id, (sigma, encoded_public_m, disclose_index, encoded_disclosed_attr))
                dump_data(os.getcwd()+ "/served_service_requests.pickle", self.service_dict)
                c.send("True".encode())
            else:
                c.send("False".encode())

    def SP_RequestService(self,title,disclose_index,Theta,encoded_disclosed_attr,encoded_public_m, pi_c, delta):
        query = "SELECT * from anon_cred WHERE title = {};".format("'" + title+"'")
        tr = fetch_data_one(self.connection, query)
        print("here")
        print(tr[0])
        print()
        print(tr[1])
        print()
        print(tr[2])
        print()
        print(tr[3])
        print()
        print(tr[4])
        print()
        print(tr[5])
        print()
        print(pickle.loads(tr[6]))
        print()
        print(pickle.loads(tr[7]))
        print()
        print(tr[8])
        print()
        print(tr[9])
        print()
        print(jsonpickle.decode(pickle.loads(tr[10])))
        print()
        print(jsonpickle.decode(pickle.loads(tr[11])))
        print()
        print(pickle.loads(tr[12]))
        print()
        print(pickle.loads(tr[13]))
        print()
        print(pickle.loads(tr[14]))
        print()
        print(pickle.loads(tr[15]))
        print()
        print(pickle.loads(tr[16]))
        print()
        print(pickle.loads(tr[17]))
        print()
        print(pickle.loads(tr[18]))
        print()
        print(pickle.loads(tr[19]))
        print()
        q = tr[8]
        #q = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/" + title+"/q.pickle")
        params = setup(q,title)
        print("params")
        print(params)
        public_params = pickle.loads(tr[11])
        #public_params = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/" + title+"/public_params.pickle")

        ans = jsonpickle.decode(public_params)
        public_params = [(FQ(ans[0][0]), FQ(ans[0][1])), self.decodeToG2(ans[1]), (FQ(ans[2][0]), FQ(ans[2][1])), self.decodeToG2(ans[3])]

        aggr_accum = pickle.loads(tr[17])
        #aggr_accum = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/" + title+"/aggregate_vk_a.pickle")
        #encoded_aggregate_vk = jsonpickle.decode(aggr_accum)
        aggr_accum = self.decodeToG2(aggr_accum)
        
        aggr_vk = pickle.loads(tr[16])
        #aggr_vk = load_data(os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/" + title+"/aggregate_vk.pickle")
        #encoded_aggregate_vk = jsonpickle.decode(aggr_vk)
        aggr_vk = self.decodeVk(aggr_vk)

        st = time.time()
        tf = VerifyCred(params, aggr_vk, Theta, disclose_index, encoded_disclosed_attr, encoded_public_m, pi_c, public_params, aggr_accum, delta)
        et = time.time()
        print("Credential verify", et-st)
        print("Verify Cred : ")
        return tf
    
    def decodeVk(self, encoded_vk):
        encoded_g2, encoded_g2x, g1y, encoded_g2y, encoded_ycG = encoded_vk
        vk = []
        vk.append(self.decodeToG2(encoded_g2))
        vk.append(self.decodeToG2(encoded_g2x))
        vk.append(g1y)
        g2y = []
        for i in range(len(encoded_g2y)):
            g2y.append(self.decodeToG2(encoded_g2y[i]))
        vk.append(g2y)
        vk.append(self.decodeToG2(encoded_ycG))
        return tuple(vk)


parser = argparse.ArgumentParser(description="Anonymous Credential Usage")
parser.add_argument("--title", type=str, default = None, required = True, help= "This is the title of the Service.")
parser.add_argument("--name", type=str, default = None, required = True, help= "This is the organization of the Service provider.")
# parser.add_argument("--ip", type=str, default = '127.0.0.1', required = False,  help= "The ip at which SP is running.")
# parser.add_argument("--port", type=str, default = None, required = True,  help= "The port on which SP is running.")
parser.add_argument("--address", type=str, default = None, required = True,  help= "The blockchain address on which SP is running.")
#parser.add_argument("--verify-address", type=str, default = None, required = True,  help= "The blockchain address on which verify contract is deployed.")
parser.add_argument("--rpc-endpoint", type=str, default = None, required = True,  help= "The node rpc endpoint through which a SP is connected to blockchain network.")
parser.add_argument('--accepts', nargs='+', help='The ACs on which the service depends on.', required= True)
parser.add_argument("--ip", type=str, default = None, required = True,  help= "The IP where SP is listening for requests")
parser.add_argument("--port", type=str, default = None, required = True,  help= "The port where SP is listening for requests")

args = parser.parse_args()

sp = ServiceProvide(args.title, args.name, args.address, args.rpc_endpoint, args.accepts, args.ip, args.port)
sp.SP_setup()
listen_thread = threading.Thread(target = sp.listen_to_requests)
listen_thread.start()