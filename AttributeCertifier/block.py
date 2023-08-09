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
load_dotenv()
db_user = os.environ['db_user']
db_ip = os.environ['db_host']
db_database = os.environ['db_database']
db_port = os.environ['db_port']
connection = psycopg2.connect(user=db_user,
                                        host=db_ip,
                                        port=db_port,
                                        database=db_database)
cursor = connection.cursor()
query="SELECT * FROM anon_cred;"
cursor.execute(query)
for id, n,t,ip,po,dep,sch,incl,q, nv,par,pp_par,vk,opk,bpk,vk_a,aggr_vk, aggr_vk_a in cursor.fetchall():
    print(id)
    print(n)
    print(t)
    print(ip)
    print(po)
    print(dep)
    print(pickle.loads(sch))
    print(pickle.loads(incl))
    print(q)
    print(nv)
    print(jsonpickle.decode(pickle.loads(par)))
    print(jsonpickle.decode(pickle.loads(pp_par)))
    print(pickle.loads(vk))
    print(pickle.loads(opk))
    print(pickle.loads(bpk))
    print(pickle.loads(vk_a))
    print(pickle.loads(aggr_vk))
    print(pickle.loads(aggr_vk_a))

