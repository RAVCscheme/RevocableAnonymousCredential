import pickle
import os
from crypto import *
import socket
def load_data(filename, default_data = None):
    value =None
    try:
        f = open(filename,'rb')
        value = pickle.load(f)
        f.close()
    except FileNotFoundError as e:
        f = open(filename,'wb')
        pickle.dump(default_data, f)
        f.close()
    return value

def dump_data(file_path, data):
    f = open(file_path,'wb')
    pickle.dump(data, f)
    f.close()

def create_initial_dir(home,dir):
    mode = 0o777
    root_dir = home + "/" + dir
    try:
        os.mkdir(root_dir, mode = mode)
    except FileExistsError as e:
        pass
    return root_dir

def encodeG2(g2):
	return (g2[0].coeffs[0].n, g2[0].coeffs[1].n, g2[1].coeffs[0].n, g2[1].coeffs[1].n)

def decodeToG2(encoded_g2):
	return (FQ2([encoded_g2[0], encoded_g2[1],]), FQ2([encoded_g2[2], encoded_g2[3],]),)

def encodeGT(g2):
	return (g2.coeffs[0].n, g2.coeffs[1].n, g2.coeffs[2].n, g2.coeffs[3].n,
			g2.coeffs[4].n, g2.coeffs[5].n, g2.coeffs[6].n, g2.coeffs[7].n,
			g2.coeffs[8].n, g2.coeffs[9].n, g2.coeffs[10].n, g2.coeffs[11].n)



def encodeG2List(g2_list):
  encoded_g2_list = []
  for g2 in g2_list:
    if g2 is not None:
      encoded_g2_list.append(encodeG2(g2))
    else:
      encoded_g2_list.append(None)
  return encoded_g2_list

def decodeToG2List(encoded_g2_list):
  g2_list = []
  for encoded_g2 in encoded_g2_list:
    if encoded_g2 is not None:
      g2_list.append(decodeToG2(encoded_g2))
    else:
      g2_list.append(None)
  return g2_list

def encodeVk(vk):
  g2, g2x, g1y, g2y = vk
  encoded_vk = []
  encoded_vk.append(encodeG2(g2))
  encoded_vk.append(encodeG2(g2x))
  encoded_vk.append(g1y)
  encoded_g2y = []
  for i in range(len(g2y)):
    encoded_g2y.append(encodeG2(g2y[i]))
  encoded_vk.append(encoded_g2y)
  return tuple(encoded_vk)

def encodeVkList(vks):
  encoded_vks = []
  for vk in vks:
    if vk is not None:
      encoded_vks.append(encodeVk(vk))
    else:
      encoded_vks.append(None)
  return encoded_vks

def decodeVkList(encoded_vks):
  vks = []
  for encoded_vk in encoded_vks:
    if encoded_vk is not None:
      vks.append(decodeVk(encoded_vk))
    else:
      vks.append(None)
  return vks

def decodeVk(encoded_vk):
  encoded_g2, encoded_g2x, g1y, encoded_g2y,encoded_ycG = encoded_vk
  vk = []
  vk.append(decodeToG2(encoded_g2))
  vk.append(decodeToG2(encoded_g2x))
  vk.append(g1y)
  g2y = []
  for i in range(len(encoded_g2y)):
    g2y.append(decodeToG2(encoded_g2y[i]))
  vk.append(g2y)
  vk.append(decodeToG2(encoded_ycG))
  return tuple(vk)

def decodeOpkList(encoded_opk):
    opk = []
    for i in encoded_opk:
      opk.append((FQ2([i[0][0], i[0][1]]), FQ2([i[1][0], i[1][1]])))
    
    return opk

def fetch_data_one(connection, query):
    cursor = connection.cursor()
    cursor.execute(query)
    ans = cursor.fetchone()
    connection.commit()
    return ans

def post_data(connection, data, table):
   cursor = connection.cursor()
   col_name = ",".join(list(data.keys()))
   value = tuple(data.values())
   print(value)
   placeholder = ",".join(["%s" for i in range(len(data))])
   p = "INSERT INTO {} ({}) VALUES({});".format(table, col_name, placeholder)
   cursor.execute(p, value)
   connection.commit()

def get_contracts():
    s = socket.socket()
    s.connect(("localhost",9999))
    f = open("contracts.zip",'wb') # Open in binary
    
    l = s.recv(1024)
    print(l)
    while (l):
        #print("f")
        f.write(l)
        l = s.recv(1024)
    f.close()
    s.close()
    os.system("unzip contracts.zip")
    os.system("rm contracts.zip")