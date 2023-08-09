import jsonpickle
import socket
import argparse
import os
from web3 import Web3
import json
import pickle
import threading
from utils import *
from crypto import *

class Validator:
    def __init__(self, id, address,title, endpoint):
        self.title = title
        self.id = id
        self.address = address
        self.connection = connect_db()
        get_contracts()
        query = "SELECT * from anon_cred WHERE title = {};".format("'" + title + "'")
        self.r = fetch_data_one(self.connection, query)
        #self.path = os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/" + self.title
        # self.q = load_data(self.path + "/q.pickle")
        self.q = self.r[8]
        self.params = setup(self.q,self.title)
        self.rpc_endpoint = endpoint
        self.contracts = self.load_contracts()
        self.vk = None
        self.sk = None
        self.kr_registry = {}
        
    
    def load_contracts(self):
        # params_address = load_data(os.getcwd()+"/ROOT/params_address.pickle")
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

    
    def register_validator(self):
        valid = load_data(self.path + "/validatorsList.pickle")
        valid.append((self.id, self.address))
        dump_data(self.path + "/validatorsList.pickle", valid)
	
    def decodeToG2(self,encoded_g2):
        return (FQ2([encoded_g2[0], encoded_g2[1],]), FQ2([encoded_g2[2], encoded_g2[3],]),)
    
    def decodeVk(self,encoded_vk):
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
    
    def requestKeys(self):
        # Register = load_data(os.getcwd()+"/ROOT/ac_register.pickle")
        # r1 = None
        # for register in Register:
        #     if register["title"] == self.title:
        #         r1 = register
        # if (r1==None):
        #     print("No such Anonymous Credentials.")
        #     return None
        # ip, port = register["ip"], register["port"]
        ip = self.r[3]
        port = self.r[4]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print ("Socket successfully created")
        except socket.error as err:
            print ("socket creation failed with error %s" %(err))
        s.connect((ip, int(port)))
        print("connected to port : ", port)
        keys = {"sk": None, "pk" : None}
        
        try:
            validator = "validator:"+self.id
            s.send(validator.encode())
            keysJSON = s.recv(8192).decode()
            keys = jsonpickle.decode(keysJSON)
            encoded_vk, sk = keys
            vk = self.decodeVk(encoded_vk)
        except Exception as e:
            s.shutdown(socket.SHUT_RDWR)
            print(e)
        finally:
            s.close()
        return (vk, sk)
    
    def setup_validator(self):
        #self.register_validator()
        (self.vk, self.sk) = self.requestKeys()
    
    def listen_to_requests(self):#Where code waits for emit event
        (w3,p,r,i,o2,a,v) = self.contracts
        request_filter = r.events.emitRequest.createFilter(fromBlock="0x0", toBlock='latest')
        credential_id = p.functions.getMapCredentials(self.title).call()
        assert credential_id != 0, "No such AC."
        while True:
            storage_log = request_filter.get_new_entries()
            for i in range(len(storage_log)):
                current_credential_id = storage_log[i]['args']['id']
                if current_credential_id != credential_id :
                    continue
                sender = storage_log[i]['args']['sender'] #string
                encoded_cm = storage_log[i]['args']['cm']
                encoded_vcerts = storage_log[i]['args']['vcerts']
                encoded_commitments = storage_log[i]['args']['commitments']
                # encoded_ciphershares = storage_log[i]['args']['ciphershares']
                public_m = storage_log[i]['args']['public_m']
                combination = storage_log[i]['args']['combination']
                validator_kr_share = storage_log[i]["args"]["validator_shares"]
                vcerts = []
                for i in range(len(encoded_vcerts)):
                    vcerts.append(((FQ(encoded_vcerts[i][0]), FQ(encoded_vcerts[i][1])), (encoded_vcerts[i][2], encoded_vcerts[i][3])))
                    cm = (FQ(encoded_cm[0]), FQ(encoded_cm[1]))
                    commitments = []
                for i in range(len(encoded_commitments)):
                    commitments.append((FQ(encoded_commitments[i][0]), FQ(encoded_commitments[i][1])))
                    # ciphershares = []
                    # for i in range(len(encoded_ciphershares)):
                    # 	ciphershares.append(((FQ2([encoded_ciphershares[i][1], encoded_ciphershares[i][0],]), FQ2([encoded_ciphershares[i][3],encoded_ciphershares[i][2],]),), (FQ2([encoded_ciphershares[i][5], encoded_ciphershares[i][4],]), FQ2([encoded_ciphershares[i][7],encoded_ciphershares[i][6],]),)))
                    # Lambda = (cm, commitments, ciphershares, public_m, vcerts, combinations)
                pending_requests = (sender, cm, commitments, public_m, vcerts, combination, validator_kr_share)
                self.issuePartialCredentials(pending_requests)
            time.sleep(10)
    
    def issuePartialCredentials(self, pending_requests):
        (w3,p,r,i,o2,a,v) = self.contracts
        (sender, cm, commitments, public_m, vcerts, combination, validator_kr_share) = pending_requests
        time.sleep(2)
        #kr = get_kr_share(sender,int(args.id))
        kr = validator_kr_share[int(self.id)-1]
        print("kr")
        print(kr)
        h = compute_hash(self.params, cm)
        _, o, _, _, _, _ = self.params
        issuing_session_id = int.from_bytes(to_binary256(h), 'big', signed=False)
        self.kr_registry.setdefault(issuing_session_id,kr)
        print("sender_kr")
        print(self.kr_registry)
        public_m_encoding = p.functions.get_public_m_encoding(self.title).call()
        encoded_public_m = []
        for i in range(len(public_m)):
            if public_m_encoding[i] == 0:
                encoded_public_m.append(int(public_m[i]))
            else:
                encoded_public_m.append(int.from_bytes(sha256(public_m[i].encode("utf8").strip()).digest(), "big") % o)
        Lambda = (cm, commitments)
        st  = time.time()
        blind_sig = BlindSignAttr(self.params, self.sk,kr,Lambda, encoded_public_m)
        et = time.time()
        print("BlindSignAttr", et-st)
        send_h = [blind_sig[0][0].n, blind_sig[0][1].n]
        send_t = [blind_sig[1][0].n, blind_sig[1][1].n]
        # Upload the blind signature to Issue.sol by Validator_1
        tx_hash = i.functions.SendBlindSign(self.title, sender, send_h, send_t).transact({'from':self.address})

parser = argparse.ArgumentParser(description="Anonymous Credential")
parser.add_argument("--title", type=str, default = None, required = True, help= "This is the title of the Anonymous Credential.")
parser.add_argument("--id", type=str, default = None, required = True,  help= "The id of the validator giving the Anonymous Credential")
parser.add_argument("--address", type=str, default = None, required = True,  help= "The blockchain address on which validator is running.")
parser.add_argument("--rpc-endpoint", type=str, default = None, required = True,  help= "The node rpc endpoint through which a validator is connected to blockchain network.")

args = parser.parse_args()
v = Validator(args.id, args.address,args.title, args.rpc_endpoint)
v.setup_validator()
listen_thread = threading.Thread(target = v.listen_to_requests)
listen_thread.start()