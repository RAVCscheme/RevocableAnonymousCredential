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
import psycopg2
from dotenv import load_dotenv

delta  = G1
acc_sc = 3749291583378862014676989402475065136209711065587427209944045838125265337048


kr1 = 6870201556096952330518023477309199119543483440721240805476706360426694178816
W1 = delta
print("k1 = ", kr1)
print("W1 = ", W1)
delta1 = multiply(delta, (acc_sc + kr1)%curve_order)
W2 =  delta1
kr2 = 2151988310135889225506137909677920014901712812565789839605088815240542400023
print("k2 = ", kr2)
print("W2 = ", W2)
delta2 = multiply(delta1, (acc_sc + kr2)%curve_order)
# print(delta)
# print(delta1)
print(delta2)
# W3 =  delta2
# kr3 = 6961590852428479403855523542456916418676706655703952936761969444943058969515
# print("k3 = ", kr3)
# print("W3 = ", W3)
# delta3 = multiply(delta2, (acc_sc + kr3)%curve_order)
# # W4 =  delta3
# # kr4 = 21330695643945194454793672790204296756230261825513513623189067198490688824782
# # print("k4 = ", kr4)
# # print("W4 = ", W4)
# # delta4 = multiply(delta3, (acc_sc + kr4)%curve_order)

# # W5 = delta4
# # kr5 = 5800230277563581489373309973517767048771528377957865759139597773267340509712
# # print("k5 = ", kr5)
# # print("W5 = ", W5)
# #delta5 = multiply(delta4, (acc_sc + kr5)%curve_order)
# W1p = multiply(delta2, modInverse((acc_sc + kr1)%curve_order, curve_order))
# print("updated witness")
# print(W1p)

r1 = multiply(W1, (kr2 - kr1) % curve_order)
print("r1")
print(r1)
W1 = add(delta1, r1)
print("r2")
print(W1)

# #r1 = multiply(W1, )

# r1 = multiply(W1, (kr3 - kr1) % curve_order)
# print("r1")
# print(r1)
# W1 = add(delta2, r1)
# print("r2")
# print(W1)


r2 = add(neg(delta1), W1)
W1 = multiply(r2, modInverse((kr2 - kr1)%curve_order, curve_order))
print("W1")
print(W1)

# # r1 = multiply(W1, (kr4 - kr1) % curve_order)
# # print("r1")
# # print(r1)
# # W1 = add(delta3, r1)
# # print("r2")
# # print(W1)

# # r1 = multiply(W1, (kr5 - kr1) % curve_order)
# # print("r1")
# # print(r1)
# # W1 = add(delta4, r1)
# # print("r2")
# # print(W1)
# #print(multiply(delta2, modInverse((acc_sc + kr1)%curve_order, curve_order)))

# # a = multiply(G1, 3+2)
# # b = multiply(G1, (2-3)%curve_order)
# # g = add(a,b)
# # print(g)
# # c = multiply(G1, 4)
# # print(c)

# Wrr = (1687804424535356617745177757740972595160885943538640028024401223242380614486, 13888397350296938266212117667299694122322073690347849702523877172497203588429)
# Wrr = (FQ(Wrr[0]), FQ(Wrr[1]))
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
connection = connect_db()
query = "SELECT address from contracts WHERE name = {};".format("'Accu'")
accumulator_address = pickle.loads(fetch_data_one(connection, query)[0])

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7547", request_kwargs = {'timeout' : 300}))

tf = json.load(open('./Blockchain/build/contracts/Accumulator.json'))
accumulator_address = Web3.toChecksumAddress(accumulator_address)
acc_contract = w3.eth.contract(address = accumulator_address, abi = tf['abi'])

delta = acc_contract.functions.get_delta().call()

print(delta)
