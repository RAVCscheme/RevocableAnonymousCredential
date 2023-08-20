import os
import datetime
import jsonpickle
from dotenv import load_dotenv
from psycopg2 import Error
import socket
from utils import *
import psycopg2



load_dotenv()
db_user = os.environ['db_user']
db_ip = os.environ['db_host']
db_database = os.environ['db_database']
db_port = os.environ['db_port']
connection = psycopg2.connect(user=db_user,
                                  host=db_ip,
                                  port=db_port,
                                  database=db_database)

DROP_TABLE_CONTRACTS = f"DROP TABLE IF EXISTS contracts;"
DROP_TABLE_CERTIFIER = f"DROP TABLE IF EXISTS certifiers;"
DROP_TABLE_ANON_CRED = f"DROP TABLE IF EXISTS anon_cred;"
DROP_TABLE_SERVICES = f"DROP TABLE IF EXISTS services;"
CREATE_CONTRACTS = f"CREATE TABLE IF NOT EXISTS contracts (ID serial PRIMARY KEY NOT NULL, NAME TEXT, ADDRESS BYTEA);"
CREATE_CERTIFIER = f"CREATE TABLE IF NOT EXISTS certifiers (ID serial PRIMARY KEY NOT NULL, NAME TEXT, TITLE TEXT, REQ_IP TEXT, REQ_PORT TEXT,OPEN_IP TEXT, OPEN_PORT TEXT,DEPENDENCY TEXT[], PARAMS BYTEA, PK BYTEA, SCHEMA BYTEA);"
CREATE_ANON_CRED = f"CREATE TABLE IF NOT EXISTS anon_cred (ID serial PRIMARY KEY NOT NULL, NAME TEXT, TITLE TEXT, IP TEXT, PORT TEXT,DEPENDENCY TEXT[], SCHEMA BYTEA, INCLUDE_INDEX BYTEA,NUM_OF_ATTRI INT,NV_NO_TV_TO INT[], PARAMS BYTEA, PP_PARAMS BYTEA, VK BYTEA, OPK BYTEA, BPK BYTEA, VK_A BYTEA, AGGR_VK BYTEA, AGGR_VK_A BYTEA, VALID_ADDR BYTEA, OPEN_ADDR BYTEA)"
CREATE_SERVICES =  f"CREATE TABLE IF NOT EXISTS services (ID serial PRIMARY KEY NOT NULL, NAME TEXT, ADDRESS BYTEA, DEPENDENCY TEXT, IP TEXT, PORT TEXT, POLICY BYTEA)"
with connection:
    with connection.cursor() as cursor:
        cursor.execute(DROP_TABLE_CONTRACTS)
        cursor.execute(DROP_TABLE_CERTIFIER)
        cursor.execute(DROP_TABLE_ANON_CRED)
        cursor.execute(DROP_TABLE_SERVICES)
        cursor.execute(CREATE_CONTRACTS)
        cursor.execute(CREATE_CERTIFIER)
        cursor.execute(CREATE_ANON_CRED)
        cursor.execute(CREATE_SERVICES)

# root_dir = create_initial_dir(os.getcwd(),"ROOT")

def uploadAddresses(name, address, filename):
    cursor = connection.cursor()
    # file_path = os.path.join(root_dir, filename)
    # f = open(file_path,'wb')
    # pickle.dump(address, f)
    text = pickle.dumps(address, 1)
    query = "INSERT INTO contracts(Name, Address) VALUES (%s,%s);"
    cursor.execute(query, (name,psycopg2.Binary(text)))    


# encoding_type_map = {"1": type("string"), "2": type(1), "3": type(datetime.datetime.now())}


# user_dir = create_initial_dir(os.getcwd() +"/ROOT", "USER")
# cer_dir = create_initial_dir(os.getcwd() +"/ROOT", "CERTIFIER")
# user_dir = create_initial_dir(os.getcwd() +"/ROOT", "SERVICES")
# user_dir = create_initial_dir(os.getcwd() +"/ROOT", "ANONYMOUS_CREDENTIALS")

# dump_data(os.getcwd() + "/ROOT/encoding_type_map.pickle",encoding_type_map)
# dump_data(os.getcwd() + "/ROOT/ca_register.pickle",[])
# dump_data(os.getcwd() + "/ROOT/service_register.pickle",[])
# dump_data(os.getcwd() + "/ROOT/ac_register.pickle",[])

os.system("truffle migrate --reset –compile-all > SC_output.txt")

with open("SC_output.txt") as file:
    lines = [line.strip().split() for line in file]
    for i in lines:
        if(len(i) < 2):
            continue
        if(i[0] == "Open"):
            uploadAddresses(i[0],i[1], "opening_address.pickle")
        elif(i[0] == "Issue"):
            uploadAddresses(i[0],i[1], "issue_address.pickle")
        elif(i[0] == "Request"):
            uploadAddresses(i[0],i[1], "request_address.pickle")
        elif(i[0] == "Params"):
            uploadAddresses(i[0],i[1], "params_address.pickle")
        elif(i[0] == "Verify"):
            uploadAddresses(i[0],i[1], "verify_address.pickle")
        elif(i[0] == "Accu"):
            uploadAddresses(i[0],i[1], "accumulator_address.pickle")

# sql = "SELECT address from contracts;"#.format("'Params'")
# cursor = connection.cursor()
# cursor.execute(sql)
 #for blob in cursor.fetcho():
#          print (blob)
connection.commit()
connection.close()

os.system("zip -r contracts.zip ./Blockchain/build/contracts")
s = socket.socket()
s.bind(("localhost",9999))
s.listen(10) # Accepts up to 10 connections.

while True:
    sc, address = s.accept()

    print(address)
    f = open("contracts.zip",'rb') #open in binary
    l = f.read(1024)
    #print(l)
    while (l):
        #print("j")
        sc.send(l)
        l = f.read(1024)
    f.close()
    sc.close()

s.close()