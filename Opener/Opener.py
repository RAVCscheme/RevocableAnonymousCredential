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

class Openers:
    def __init__(self,title, id,ip, port, address, rpc_endpoint):
        self.title = title
        self.id = id
        self.ip = ip
        self.port = port
        self.address = address
        self.endpoint = rpc_endpoint
        get_contracts()
        self.path = os.getcwd() + "/ROOT/ANONYMOUS_CREDENTIALS/" + self.title
        self.registry = {}
        self.connection = connect_db()
        query = "SELECT * from anon_cred WHERE title = {};".format("'" + title + "'")
        self.r = fetch_data_one(self.connection, query)
        self.q = self.r[8]
        #self.q = load_data(self.path +"/q.pickle")
        self.no = self.r[9][1]
        #self.no = load_data(self.path +"/no.pickle")
        self.to = self.r[9][3]
        #self.to = load_data(self.path +"/to.pickle")
        self.params = setup(self.q,self.title)
        self.schema = pickle.loads(self.r[6])
        #self.schema = load_data(self.path+"/schema.pickle")
        self.aggr_vk = pickle.loads(self.r[16])
        #self.aggr_vk = load_data(self.path+"/aggregate_vk.pickle")
        #encoded_aggregate_vk = jsonpickle.decode(self.aggr_vk)
        self.aggr_vk = self.decodeVk(self.aggr_vk)
        self.aggr_accum = pickle.loads(self.r[17])
        #self.aggr_accum = load_data(self.path+"/aggregate_vk_a.pickle")
        #encoded_aggregate_vk = jsonpickle.decode(self.aggr_accum)
        self.aggr_accum = decodeToG2(self.aggr_accum)
        self.opks = None
        self.osks = None
        self.accum_pk = None
        self.accum_sk = None
        self.bsk = None
        self.bpk = None
        #j = load_data(self.path+"/anon_cred_ip_port")
        self.anon_ip = self.r[3]
        self.anon_port = self.r[4]
        self.contracts = None
    
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

    def registerOpener(self):
        valid = load_data(self.path + "/openersList.pickle")
        valid.append((self.id, self.address))
        dump_data(self.path + "/openersList.pickle", valid)
    
    def decodeToG2(self,encoded_g2):
        return (FQ2([encoded_g2[0], encoded_g2[1],]), FQ2([encoded_g2[2], encoded_g2[3],]),)
    
    def get_keys(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print ("Socket successfully created")
        except socket.error as err:
            print ("socket creation failed with error %s" %(err))
        s.connect((self.anon_ip, int(self.anon_port)))
        print("connected to port : ", self.anon_port)
        opener = "opener:"+self.id
        s.send(opener.encode())
        keysJSON = s.recv(8192).decode()
        keys = jsonpickle.decode(keysJSON)
        print(keys)
        enc_opks, self.osks, encoded_vk_a, self.accum_sk, encoded_bpk, self.bsk = keys
        self.accum_pk = self.decodeToG2(encoded_vk_a)
        print("accum_pk")
        print(self.accum_pk)
        self.opks = self.decodeToG2(enc_opks)
        print("opks")
        print(self.opks)
        #print("keys")
        self.bpk = (FQ(encoded_bpk[0]),FQ(encoded_bpk[1]))
        print("bpk")
        print(self.bpk)
		# print(sk_a)
		# print(vk_a)
        s.shutdown(socket.SHUT_RDWR)
        s.close()

    def load_contracts(self):
        # params_address = load_data(os.getcwd()+"/ROOT/params_address.pickle")
        # request_address = load_data(os.getcwd()+"/ROOT/request_address.pickle")
        # issue_address = load_data(os.getcwd()+"/ROOT/issue_address.pickle")
        # opening_address = load_data(os.getcwd()+"/ROOT/opening_address.pickle")
        # accumulator_address  = load_data(os.getcwd()+"/ROOT/accumulator_address.pickle")

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
        
        w3 = Web3(Web3.HTTPProvider(self.endpoint, request_kwargs = {'timeout' : 300}))
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

    def setup_opener(self):
        self.get_keys()
        (w3, para, request, issue, open, acc) = self.load_contracts()
        self.contracts = (w3, para, request, issue, open, acc)

    def set_registry(self,credential_id,sender,cm, ciphershares, public_m, vcerts,kr,combinations):
        h = compute_hash(self.params, cm)
        _, _, _, beta,ycG = self.aggr_vk
        _, o, _, _, _, _ = self.params
        issuing_session_id = int.from_bytes(to_binary256(h), 'big', signed=False)
        self.registry[credential_id].setdefault(issuing_session_id, {})
        self.registry[credential_id][issuing_session_id].setdefault("private-share", add(elgamal_dec(self.params, self.osks, ciphershares) ,multiply(ycG,kr)))
        j = 0
        i = 0
        public_share = None
        for key in self.schema:
            if self.schema[key]["visibility"] == "public":
                if self.schema[key]["type"] == "str":
                    public_share = add(public_share, multiply(beta[i], (int.from_bytes(sha256(public_m[j].encode("utf8").strip()).digest(), "big") % o) ))
                else:
                    public_share = add(public_share, multiply(beta[i], public_m[j]))
                j += 1
            i+=1
            
        self.registry[credential_id][issuing_session_id].setdefault("public-share", public_share) # it contains attributes in the order of schemaOrder
        self.registry[credential_id][issuing_session_id].setdefault("vcerts", vcerts)
        self.registry[credential_id][issuing_session_id].setdefault("combinations", combinations)
        self.registry[credential_id][issuing_session_id].setdefault("kr", kr)


    def revoke_cred(self):
        (w3,params_contract, request_contract, issue_contract, _,acc_contract) = self.contracts
        acc_filter = acc_contract.events.send_self_revocation.createFilter(fromBlock="0x0", toBlock='latest')
        combine_s = acc_contract.events.send_s.createFilter(fromBlock="0x0", toBlock='latest')
        combine_d_e = acc_contract.events.send_d_and_e.createFilter(fromBlock="0x0", toBlock='latest')
        while True:
            storage_log_2 = acc_filter.get_new_entries()
            for i in range(len(storage_log_2)):
                kr = storage_log_2[i]['args']['kr']
                W = storage_log_2[i]['args']['W']
                H = storage_log_2[i]['args']['H']
                S = storage_log_2[i]['args']['S']
                cm = storage_log_2[i]['args']['cm']
                G1r = storage_log_2[i]['args']['g1_r']
                a_share = storage_log_2[i]['args']['a_share'][int(self.id)-1]
                b_share = storage_log_2[i]['args']['b_share'][int(self.id)-1]
                c_share = storage_log_2[i]['args']['c_share'][int(self.id)-1]
                #t = storage_log_2[i]["args"]["t"]
                print("G1r")
                print(G1r)
                print("a_share")
                print(a_share)
                print("b_share")
                print(b_share)
                print("c_share")
                print(c_share)
                # print("t")
                # print(t)
                delta = acc_contract.functions.get_delta().call()
                delta = (FQ(delta[0]), FQ(delta[1]))
                W = (FQ(W[0]), FQ(W[1]))
                H = (FQ(H[0]), FQ(H[1]))
                S = (FQ(S[0]), FQ(S[1]))
                G1r = (FQ(G1r[0]), FQ(G1r[1]))
                acm = []
                for i in cm:
                    acm.append((FQ(i[0]), FQ(i[1])))
                
                if(W[0] != 0 and W[1] != 0):
                    st = time.time()
                    tf = VerifyRevokeCred(kr,W,H,S,acm, delta, self.aggr_accum,self.aggr_vk)
                    et = time.time()
                    print("kr_verify_time", et-st)
                    print("tf")
                    print(tf)
                # decrypt ai, bi, ci shares
                hash = int.from_bytes(to_binary256(multiply(G1r, self.bsk)), "big", signed=False)
                print("hash")
                print(hash)
                ai =  hash^a_share
                bi =  hash^b_share
                ci =  hash^c_share
                print(ai)
                print(bi)
                print(ci)
                ri = genRandom()
                # compute di, ei
                di = (self.accum_sk + kr - ai)%curve_order
                ei = (ri - bi) %curve_order
                #time.sleep(5)
                
                # wait for combine event
                d = None
                e = None
                asd = False
                flag = True
                while True:
                    logg = combine_d_e.get_new_entries()
                    # recieve d, e
                    
                    for i in range(len(logg)):
                        asd = True
                        d = int(logg[i]["args"]["d"])
                        e = int(logg[i]["args"]["e"])
                    if asd:
                        break

                    if flag:
                        tx_hash = acc_contract.functions.combine_di_and_ei(di,ei,int(self.id)).transact({'from': self.address, 'gas': 100000000})
                        w3.eth.waitForTransactionReceipt(tx_hash)
                        flag = False
                    
                print("d")
                print(d)
                print("e")
                print(e)
                # compute si
                si = ((d*bi)%curve_order + (e*ai)%curve_order + ci + (d*e) %curve_order)%curve_order
                
                
                s = None
                asd = False
                flag = True
                while True:
                    # wait for combine event
                    logg = combine_s.get_new_entries()
                    
                    for i in range(len(logg)):
                        asd = True
                        # recieve s
                        s = int(logg[i]["args"]["s"])
                    if asd:
                        break
                    if flag:
                        tx_hash = acc_contract.functions.combine_func_si(si,int(self.id)).transact({'from': self.address, 'gas': 100000000})
                        w3.eth.waitForTransactionReceipt(tx_hash)
                        flag = False
                print("s")
                print(s)
                pi = (modInverse(s,curve_order) * ri)%curve_order
                # delta = acc_contract.functions.get_delta().call()
                # delta = (FQ(delta[0]), FQ(delta[1]))
                # pi = multiply(delta, pi)
                # pi = (pi[0].n,pi[1].n)
                # # compute s^-1*r and then delta^pi
                # print("pi")
                # print(pi)
                # ans = compute_hash(self.params, cm)
                # req_id = s = int.from_bytes(to_binary256(ans), 'big', signed=False)
                st = time.time()
                tx_hash = acc_contract.functions.recieve_share_for_revocation(int(self.id),pi,self.cred_pr_id).transact({'from': self.address, 'gas': 100000000})
                w3.eth.waitForTransactionReceipt(tx_hash)
                et = time.time()
                delta = acc_contract.functions.get_delta().call()
                print(delta)
                print("recieve_ya_share_time", et-st)

    def request_listener(self):
        (w3,params_contract, request_contract, issue_contract, _,acc_contract) = self.contracts
        request_filter = request_contract.events.emitRequest.createFilter(fromBlock="0x0", toBlock='latest')
        #acc_filter = acc_contract.events.send_self_revocation.createFilter(fromBlock="0x0", toBlock='latest')
        issue_filter = issue_contract.events.get_ya_shares.createFilter(fromBlock="0x0", toBlock='latest')
        credential_id = params_contract.functions.getMapCredentials(args.title).call()
        #combine_s = acc_contract.events.send_s.createFilter(fromBlock="0x0", toBlock='latest')
        #combine_d_e = acc_contract.events.send_d_and_e.createFilter(fromBlock="0x0", toBlock='latest')
        delta = acc_contract.functions.get_delta().call()
        delta = (FQ(delta[0]), FQ(delta[1]))
        print("delta before")
        print(delta)
        self.registry.setdefault(credential_id, {})
        assert credential_id != 0, "No such AC."
        while True:
            storage_log = request_filter.get_new_entries()
            #storage_log_2 = acc_filter.get_new_entries()
            for i in range(len(storage_log)):
                delta = acc_contract.functions.get_delta().call()
                delta = (FQ(delta[0]), FQ(delta[1]))
                time.sleep(1)
                current_credential_id = storage_log[i]['args']['id']
                if current_credential_id != credential_id :
                    continue
                sender = storage_log[i]['args']['sender'] #string
                #kr = get_kr_share(sender,int(args.id))
			
                encoded_cm = storage_log[i]['args']['cm']
                encoded_vcerts = storage_log[i]['args']['vcerts']
                encoded_commitments = storage_log[i]['args']['commitments']
                encoded_ciphershares = storage_log[i]['args']['ciphershares']
                public_m = storage_log[i]['args']['public_m']
                combination = storage_log[i]['args']['combination']
                opener_kr_share = storage_log[i]["args"]["opener_shares"]
                aggr_kr = aggr([int(i) for i in opener_kr_share])
                print("aggr_kr")
                print(aggr_kr)
                kr = int(opener_kr_share[int(args.id)-1])
                print("kr")
                print(kr)
                vcerts = []
                for i in range(len(encoded_vcerts)):
                    vcerts.append(((FQ(encoded_vcerts[i][0]), FQ(encoded_vcerts[i][1])), (encoded_vcerts[i][2], encoded_vcerts[i][3])))
                cm = (FQ(encoded_cm[0]), FQ(encoded_cm[1]))
                commitments = []
                for i in range(len(encoded_commitments)):
                    commitments.append((FQ(encoded_commitments[i][0]), FQ(encoded_commitments[i][1])))
                ciphershares = []
                for i in range(len(encoded_ciphershares)):
                    ciphershares.append(((FQ2([encoded_ciphershares[i][1], encoded_ciphershares[i][0],]), FQ2([encoded_ciphershares[i][3],encoded_ciphershares[i][2],]),), (FQ2([encoded_ciphershares[i][5], encoded_ciphershares[i][4],]), FQ2([encoded_ciphershares[i][7],encoded_ciphershares[i][6],]),)))
                Lambda = (cm, commitments, ciphershares, public_m, vcerts)
                self.set_registry(credential_id, sender,cm, ciphershares[int(args.id)-1], public_m, vcerts,kr, combination)
                asd = False
                while True:
                    storage_log = issue_filter.get_new_entries()
                    for i in range(len(storage_log)):
                        asd = True
                        current_credential_id = storage_log[i]['args']['id']
                        print("current_id")
                        print(current_credential_id)
                        if current_credential_id != credential_id :
                            continue
                        ans = compute_hash(self.params, cm)
                        s = int.from_bytes(to_binary256(ans), 'big', signed=False)
                        self.cred_pr_id = s
                        # a1 = multiply(delta, (self.accum_sk + kr) % curve_order)
                        # a1 = (a1[0].n, a1[1].n)
                        a1 = (self.accum_sk + kr) % curve_order
                        tx_hash = acc_contract.functions.recieve_ya_share(int(self.id),a1,s).transact({'from': self.address, 'gas': 100000000})
                        w3.eth.waitForTransactionReceipt(tx_hash)
                        # delta = acc_contract.functions.get_delta().call()
                        # print("delta after")
                        # print(delta)
                    if asd:
                        break
            # for i in range(len(storage_log_2)):
            #     kr = storage_log_2[i]['args']['kr']
            #     W = storage_log_2[i]['args']['W']
            #     H = storage_log_2[i]['args']['H']
            #     S = storage_log_2[i]['args']['S']
            #     cm = storage_log_2[i]['args']['cm']
            #     G1r = storage_log_2[i]['args']['g1_r']
            #     a_share = storage_log_2[i]['args']['a_share'][int(self.id)-1]
            #     b_share = storage_log_2[i]['args']['b_share'][int(self.id)-1]
            #     c_share = storage_log_2[i]['args']['c_share'][int(self.id)-1]
            #     print("G1r")
            #     print(G1r)
            #     print("a_share")
            #     print(a_share)
            #     print("b_share")
            #     print(b_share)
            #     print("c_share")
            #     print(c_share)
            #     delta = acc_contract.functions.get_delta().call()
            #     delta = (FQ(delta[0]), FQ(delta[1]))
            #     W = (FQ(W[0]), FQ(W[1]))
            #     H = (FQ(H[0]), FQ(H[1]))
            #     S = (FQ(S[0]), FQ(S[1]))
            #     G1r = (FQ(G1r[0]), FQ(G1r[1]))
            #     acm = []
            #     for i in cm:
            #         acm.append((FQ(i[0]), FQ(i[1])))
            #     st = time.time()
            #     tf = VerifyRevokeCred(kr,W,H,S,acm, delta, self.aggr_accum,self.aggr_vk)
            #     et = time.time()
            #     print("kr_verify_time", et-st)
            #     print("tf")
            #     print(tf)
            #     # decrypt ai, bi, ci shares
            #     hash = int.from_bytes(to_binary256(multiply(G1r, self.bsk)), "big", signed=False)
            #     ai =  hash^a_share
            #     bi =  hash^a_share
            #     ci =  hash^a_share
            #     ri = genRandom()
            #     # compute di, ei
            #     di = (self.accum_sk + kr - ai)%curve_order
            #     ei = (ri - bi) %curve_order
            #     #time.sleep(5)
                
                
            #     # wait for combine event
            #     d = None
            #     e = None
            #     asd = False
            #     flag = True
            #     while True:
            #         logg = combine_d_e.get_new_entries()
            #         # recieve d, e
                    
            #         for i in range(len(logg)):
            #             asd = True
            #             d = int(logg[i]["args"]["d"])
            #             e = int(logg[i]["args"]["e"])
            #         if asd:
            #             break

            #         if flag:
            #             tx_hash = acc_contract.functions.combine_di_and_ei(di,ei,int(self.id)).transact({'from': self.address, 'gas': 100000000})
            #             w3.eth.waitForTransactionReceipt(tx_hash)
            #             flag = False
                    
            #     print("d")
            #     print(d)
            #     print("e")
            #     print(e)
            #     # compute si
            #     si = ((d*bi)%curve_order + (e*ai)%curve_order + ci + (d*e) %curve_order)%curve_order
                
                
            #     s = None
            #     asd = False
            #     flag = True
            #     while True:
            #         # wait for combine event
            #         logg = combine_s.get_new_entries()
                    
            #         for i in range(len(logg)):
            #             asd = True
            #             # recieve s
            #             s = int(logg[i]["args"]["s"])
            #         if asd:
            #             break
            #         if flag:
            #             tx_hash = acc_contract.functions.combine_func_si(si,int(self.id)).transact({'from': self.address, 'gas': 100000000})
            #             w3.eth.waitForTransactionReceipt(tx_hash)
            #             flag = False
            #     print("s")
            #     print(s)
            #     pi = (modInverse(s,curve_order) * ri)%curve_order
            #     # delta = acc_contract.functions.get_delta().call()
            #     # delta = (FQ(delta[0]), FQ(delta[1]))
            #     # pi = multiply(delta, pi)
            #     # pi = (pi[0].n,pi[1].n)
            #     # # compute s^-1*r and then delta^pi
            #     # print("pi")
            #     # print(pi)
            #     # ans = compute_hash(self.params, cm)
            #     # req_id = s = int.from_bytes(to_binary256(ans), 'big', signed=False)
            #     st = time.time()
            #     tx_hash = acc_contract.functions.recieve_share_for_revocation(int(self.id),pi,self.cred_pr_id).transact({'from': self.address, 'gas': 100000000})
            #     w3.eth.waitForTransactionReceipt(tx_hash)
            #     et = time.time()
            #     delta = acc_contract.functions.get_delta().call()
            #     print(delta)
            #     print("recieve_ya_share_time", et-st)
            #print("fgh")
            time.sleep(5)
    
    def opening_thread(self):
        (w3,params_contract, request_contract, issue_contract, opening_contract,acc_contract) = self.contracts
        credential_id = params_contract.functions.getMapCredentials(self.title).call()
        assert credential_id != 0, "No such AC."
        opening_filter = opening_contract.events.emitOpening.createFilter(fromBlock="0x0", toBlock='latest')
        revok_status_2 = acc_contract.events.revocation_complete().createFilter(fromBlock="0x0", toBlock='latest')
        revok_status = acc_contract.events.send_kr().createFilter(fromBlock="0x0", toBlock='latest')

        openersList = pickle.loads(self.r[19])
        #openersList = load_data(self.path +"/openersList.pickle")
        opener_dict = {}
        i = 1
        for opener in openersList:
            opener_dict.setdefault(opener, i)
            i+=1
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.ip, int(self.port)))        
        print ("Opener "+ self.id + " binded to %s" %(self.port))
        s.listen(10)    
        print ("Opener "+ self.id +" is listening")
        while True:
            c, addr = s.accept()
            print("Opening request is received")
            sigmaJSON = c.recv(8192).decode()
            open_sigma = jsonpickle.decode(sigmaJSON)
            opening_session_id = int.from_bytes(to_binary256(open_sigma[0]), 'big', signed=False)
            st = time.time()
            shareRegistry = PreOpening(self.params, self.registry[credential_id], open_sigma)
            send_open_shares = []
            for issuing_session_id in shareRegistry:
                shares = shareRegistry[issuing_session_id]
                pairing_values = [0]* 13
                pairing_values[0] = issuing_session_id
                for i in range(12):
                    pairing_values[i+1] = shares.coeffs[i].n
                send_open_shares.append(pairing_values)
        
            tx_hash = opening_contract.functions.SendOpeningInfo(args.title, opening_session_id, send_open_shares).transact({'from': args.address})
            # opener_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
            Reg = self.opening_event_filter(opening_filter, opener_dict, credential_id)
            print("Reg = ", Reg)
            ret_shares = {}
            indexes = [] # opener-ids
            for opener_id in Reg:
                indexes.append(int(opener_id))
                ret_shares.setdefault(int(opener_id), {})
                ret_shares[int(opener_id)] = Reg[opener_id]
            
            issuing_session_id = OpenCred(self.params, ret_shares, indexes, open_sigma, self.to, self.registry[credential_id], self.aggr_vk)
            et = time.time()
            print("Credential openeing", et-st)
            print("kr = " + str(self.registry[credential_id][issuing_session_id]["kr"]))
            kr = self.registry[credential_id][issuing_session_id]["kr"]

            acc_contract.functions.combine_func_kr(kr,int(self.id)).transact({'from':args.address,'gas': 100000000})
            asd = False
            aggr_kr = None
            while True:
                logg = revok_status.get_new_entries()        
                for i in range(len(logg)):
                    asd = True
                    # recieve s
                    aggr_kr = int(logg[i]["args"]["kr"])
                    print("aggr_kr")
                    print(aggr_kr)
                if asd:
                    break
            if(aggr_kr is not None):
                name = self.title
                a1 = (0,0)
                H = (0,0)
                S = (0,0)
                comm = [(0,0)]
                if(int(self.id) == 1):
                    acc_contract.functions.verify_revocation_request(name, aggr_kr,a1, H, S, comm).transact({'from':args.address,'gas': 100000000})
                asd = False
                while True:
                    logg = revok_status_2.get_new_entries()        
                    for i in range(len(logg)):
                        asd = True
                        # recieve s
                        bbb = int(logg[i]["args"]["c"])
                        print("revocation complete")
                        print(bbb)
                    if asd:
                        break
            # if issuing_session_id == None:
            #     print("No user matched")
            # else:
            #     vcerts = self.registry[credential_id][issuing_session_id]["vcerts"]
            #     combination = self.registry[credential_id][issuing_session_id]["combinations"]
            #     print("Which CA Do you want to query ?")
            #     for i in range(len(combination)):
            #         print("Enter "+str(i)+" for "+combination[i])
            #     ca_index = int(input())
            #     vcert = vcerts[ca_index]
            #     #ca_ip, ca_port = self.getCAIpPort(combination[ca_index])
            #     query = "SELECT * from certifiers WHERE title = {};".format("'" + combination[ca_index] + "'")
            #     m = fetch_data_one(self.connection, query)[0]
            #     ca_ip = m[5]
            #     ca_port = m[6]
            #     c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #     c.connect((ca_ip, int(ca_port)))
            #     vcertJSON = jsonpickle.encode(vcert)
            #     c.send(vcertJSON.encode())
            #     attributesJSON = c.recv(8192).decode()
            #     attributes = jsonpickle.decode(attributesJSON)
            #     if attributes is None:
            #         print("CA refused to disclose the user attributes") # Can configure to get the name of the CA.
            #     else:
            #         print("The user is : ")
            #         print(attributes)
            #     c.close()
    
    def opening_event_filter(self,opening_filter, opener_dict, credential_id):
        Reg = {}
        while True:
            opening_log = opening_filter.get_new_entries()
            for i in range(len(opening_log)):
                _credential_id = opening_log[i]['args']['id']
                if _credential_id != credential_id:
                    continue
                opening_session_id = opening_log[i]['args']['opening_session_id']
                print("opening_sess_id")
                
                opener_address = opening_log[i]['args']['opener_address'] # deduce opener id from this.
                opener_id = opener_dict[opener_address]
                # indexes.add(opener_id)
                openingshares = opening_log[i]['args']['openingshares']
                print(openingshares)
                Reg.setdefault(opener_id, {})
                for j in range(len(openingshares)):
                    issuing_session_id = openingshares[j][0]
                    pairing_share = FQ12(openingshares[j][1:13])
                    Reg[opener_id].setdefault(issuing_session_id, pairing_share) # have to map here opener id to Reg.
                if len(Reg.keys()) == self.no:
                    return Reg
                time.sleep(2)
    
    def getCAIpPort(self,title):
        RegisteredList = load_data(os.getcwd() + "/ROOT/ca_register.pickle")
        for register in RegisteredList:
            if register["title"] == title:
                return (register["open-ip"], register["open-port"])
        return None

parser = argparse.ArgumentParser(description="Anonymous Credential Threshold Opening")
parser.add_argument("--title", type=str, default = None, required = True, help= "This is the title of the Anonymous Credential.")
parser.add_argument("--id", type=str, default = None, required = True,  help= "The id of the opener in the Anonymous Credential")
parser.add_argument("--ip", type=str, default = '127.0.0.1', required = False,  help= "The ip at which Attribute Certifier is running.")
parser.add_argument("--port", type=str, default = None, required = True,  help= "The port on which Attribute Certifier is running.")
parser.add_argument("--address", type=str, default = None, required = True,  help= "The blockchain address on which opener is running.")
parser.add_argument("--rpc-endpoint", type=str, default = None, required = True,  help= "The node rpc endpoint through which a opener is connected to blockchain network.")
args = parser.parse_args()

b = Openers(args.title, args.id, args.ip, args.port, args.address, args.rpc_endpoint)
b.setup_opener()
listen_thread  = threading.Thread(target = b.request_listener)
listen_thread.start()
revoke_thread  = threading.Thread(target = b.revoke_cred)
revoke_thread.start()
opening_thread  = threading.Thread(target = b.opening_thread)
opening_thread.start()


