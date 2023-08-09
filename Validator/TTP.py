from py_ecc.bn128 import * 
from hashlib import sha256
import random

def genRandom():
	o = int(curve_order)
	return random.randint(2, o)

def FindYforX(x) :
    beta = (pow(x, 3, field_modulus) + 3) % field_modulus
    y = pow(beta, (field_modulus + 1) //4, field_modulus)
    return (beta, y)

def hashG1(byte_string):
    beta = 0
    y = 0
    x = int.from_bytes(byte_string, "big") % curve_order
    while True :
        (beta, y) = FindYforX(x)
        if beta == pow(y, 2, field_modulus) :
            return (FQ(x), FQ(y))
        x = (x + 1) % field_modulus

def ttp_setup(q, ttp):
	assert q > 0
	hs = [hashG1((ttp+("h%s")% i).encode("utf8")) for i in range(q)]
	return ((FQ, FQ2, FQ12), G1, int(curve_order), hs)

def ttpKeyGen(params):
	_, g, o, hs = params
	sk = random.randint(2, o)
	pk = multiply(g, sk)
	return pk, sk

def encode_attributes(attr, encode_str):
	o = int(curve_order)
	encoded_attr = []
	assert len(attr) == len(encode_str), "mismatch in encoding lengths"
	for i in range(len(attr)):
		if encode_str[i] == "str":
			Chash = sha256(attr[i].encode("utf8").strip()).digest()
			encoded_attr.append(int.from_bytes(Chash, "big") % o)
		else:
			encoded_attr.append(attr[i])
	return encoded_attr

def GenCommitment(params, encoded_attr):
	_, g, o, hs = params 
	Aw = [multiply(hs[i], encoded_attr[i]) for i in range(len(hs))]
	comm = multiply(g, encoded_attr[len(hs)])
	for i in range(0, len(Aw)):
		comm = add(comm, Aw[i])
	return comm

def toChallenge(element_list):
	"""Packages a challenge in a bijective way"""
	Cstring = SHA256(element_list[0])
	for i in range(1, len(element_list)):
		Cstring += SHA256(element_list[i])
	Chash = sha256(Cstring).digest()
	return (int.from_bytes(Chash, "big"))

def SHA256(element):
	return sha256((element[0].n).to_bytes(32, 'big') + (element[1].n).to_bytes(32, 'big')).digest()

	
def GenZKPoK(params, prev_params, prev_vcerts, all_enc_attr, comm):
	_, g, o, hs= params
	total_wm = [[random.randint(2, o) for _ in range(len(all_enc_attr[i]))] for i in range(len(all_enc_attr))]
	for i in range(1, len(total_wm)):
		total_wm[i][0] = total_wm[0][0]
	Aw = []
	comm_list = []
	for i in range(len(prev_vcerts)):
		(_, ttp_g, _, ttp_hs) = prev_params[i]
		tmp = multiply(ttp_g, total_wm[i][-1])
		for j in range(len(total_wm[i]) - 1):
			tmp = add(tmp, multiply(ttp_hs[j], total_wm[i][j]))
		Aw.append(tmp)
		comm_list.append(prev_vcerts[i][0])

	_tmp = multiply(g, total_wm[len(prev_vcerts)][-1])
	_tmp = add(_tmp, multiply(hs[0], total_wm[len(prev_vcerts)][0]))
	Aw.append(_tmp)
	comm_list.append(comm)

	element_list = [g] + Aw + comm_list + hs 
	c = toChallenge(element_list) % o
	total_rm = [[(total_wm[i][j] - c*all_enc_attr[i][j]) % o for j in range(len(total_wm[i]))] for i in range(len(total_wm))]
	return (c, total_rm)

def VerifyZKPoK(params, prev_params, prev_vcerts, encoded_attr, comm, ZKPoK):
	c, total_rm = ZKPoK
	for i in range(1, len(total_rm)):
		if total_rm[0][0] != total_rm[i][0]:
			return False

	_, g, o, hs= params

	tmp_comm = multiply(hs[1], encoded_attr[0])

	for i in range(2, len(hs)):
		tmp_comm = add(tmp_comm, multiply(hs[i], encoded_attr[i-1]))
	tmp_comm = add(comm, neg(tmp_comm))

	comm_list = []
	Aw = []
	for i in range(len(prev_vcerts)):
		(_, ttp_g, _, ttp_hs) = prev_params[i]
		tmp = multiply(ttp_g, total_rm[i][-1])
		for j in range(len(total_rm[i]) - 1):
			tmp = add(tmp, multiply(ttp_hs[j], total_rm[i][j]))
		tmp = add(tmp, multiply(prev_vcerts[i][0], c))
		Aw.append(tmp)
		comm_list.append(prev_vcerts[i][0])

	_, g, o, hs= params
	_tmp = multiply(g, total_rm[len(prev_vcerts)][-1])
	_tmp = add(_tmp, multiply(hs[0], total_rm[len(prev_vcerts)][0]))
	_tmp = add(_tmp, multiply(tmp_comm,c))
	Aw.append(_tmp)
	comm_list.append(comm)

	element_list = [g]+ Aw + comm_list + hs
	return (c == toChallenge(element_list) % o)

def SignCommitment(params, sk, comm):
	G, g, o, hs= params
	digest = SHA256(comm)
	sign = do_ecdsa_sign(sk, digest)
	return sign

def modInverse(a, m):
    m0 = m
    y = 0
    x = 1
 
    if (m == 1):
        return 0
 
    while (a > 1):
 
        # q is quotient
        q = a // m
 
        t = m
 
        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y
 
        # Update x and y
        y = x - q * y
        x = t
 
    # Make x positive
    if (x < 0):
        x = x + m0
 
    return x

def VerifyVcerts(params, pk, sign, digest):
	return do_ecdsa_verify(pk, sign, digest)

def do_ecdsa_sign(sk, digest):
	r = 0
	s = 0
	o = int(curve_order)
	int_digest = int.from_bytes(digest, "big") % o
	while r == 0 or s==0 :
		k = random.randint(2, o)
		p1 = multiply(G1, k)
		r = p1[0].n
		s = (modInverse(k, o) * (int_digest + ((sk * r) % o)) ) %o
	return (r, s)

def do_ecdsa_verify(pk, sign, digest):
	(r, s) = sign
	o = int(curve_order)
	int_digest = int.from_bytes(digest, "big") % o
	s1 = modInverse(s, o)
	x1 = (int_digest * s1) % o
	x2 = (r * s1) % o
	pt1 = multiply(G1, x1)
	pt2 = multiply(pk, x2)
	
	_r = add(pt1, pt2)
	
	return r == _r[0].n