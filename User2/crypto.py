from py_ecc.bn128 import *
from TTP import *
from hashlib import sha256 
from binascii import hexlify, unhexlify
import random
import time

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
        if beta == pow(y, 2, field_modulus):
            return(FQ(x), FQ(y))
        x = (x + 1) % field_modulus

def setup(q=1, AC = "h"):
    assert q > 0
    hs = [hashG1((AC+"%s"%i).encode("utf8")) for i in range(q)]
    return ((FQ, FQ2, FQ12), curve_order, G1, hs, G2, pairing)

def poly_eval(coeff, x):
    """ evaluate a polynomial defined by the list of coefficient coeff at point x """
    return sum([coeff[i] * ((x) ** i) for i in range(len(coeff))])

def ttp_keygen(params, t, n):
    (G, o, g1, hs, g2, e) = params
    q = len(hs)
    assert n >= t and t > 0 and q > 0
    # generate polynomials
    v = [random.randint(2, o) for _ in range(0,t)]
    w = [[random.randint(2, o) for _ in range(0,t)] for _ in range(q)]
    # generate shares
    yc = genRandom()
    print("yc")
    print(yc)
    Gyc = multiply(g2,yc)
    print("Gyc")
    print(Gyc)
    x = [poly_eval(v,i) % o for i in range(1,n+1)]
    y = [[poly_eval(wj,i) % o for wj in w] for i in range(1,n+1)]
    # set keys
    sk = list(zip(x, y))
    sk = [(i[0],i[1],yc) for i in sk]
    print("sk")
    print(sk)
    vk = [(g2, multiply(g2, x[i]), [multiply(g1, y[i][j]) for j in range(len(y[i]))], [multiply(g2, y[i][j]) for j in range(len(y[i]))], Gyc) for i in range(len(sk))]
    print("vk")
    print(vk)

    return (sk, vk)


def create_accumulator_shares(o,no,nv,to,tv):
    kr = genRandom()
    print("kr")
    print(kr)
    opener = [genRandom() for _ in range(0,to)]
    opener[0] = kr
    print("opener")
    print(opener)
    sk = [poly_eval(opener,i) % o for i in range(1,no+1)]

    validator = [genRandom() for _ in range(0,tv)]
    
    validator[0] = kr
    print("validator")
    print(validator)
    sk2 = [poly_eval(validator,i) % o for i in range(1,nv+1)]

    return [kr,sk,sk2]

def create_beaver_shares(kr,no,nv,to,tv):
    print("kr")
    print(kr)
    opener = [genRandom() for _ in range(0,to)]
    opener[0] = kr
    print("opener")
    print(opener)
    sk = [poly_eval(opener,i) % curve_order for i in range(1,no+1)]
    return [kr,sk]
    
def ttp_accumelator_keygen(params,t,n):
    (_,o,_,_,g2,_) = params
    assert n >= t and t > 0
    v = [random.randint(2, o) for _ in range(0,t)]
    print("accumulator_secret_key")
    print(v[0])
    sk = [poly_eval(v,i) % o for i in range(1,n+1)]
    vk = [multiply(g2,i) for i in sk]

    return (sk,vk)

def aggr(s):
    filter = [s[i] for i in range(len(s)) if s[i] is not None]
    indexes = [i+1 for i in range(len(s)) if s[i] is not None]

    l = lagrange_basis(indexes,curve_order)
    kr = 0
    for i in range(len(filter)):
        kr += ((l[i]*s[indexes[i]-1])%curve_order)
        kr = kr%curve_order
    return kr


def agg_key_accumulator(params, vk):
    (G, o, g1, hs, g2, e) = params

    filter = [vk[i] for i in range(len(vk)) if vk[i] is not None]
    indexes = [i+1 for i in range(len(vk)) if vk[i] is not None]

    l = lagrange_basis(indexes,o)

    aggr_vk = ec_sum([multiply(filter[i],  l[i]) for i in range(len(filter))])

    return aggr_vk


def to_binary256(point) :
    if isinstance(point, str):
        return sha256(point.encode("utf8").strip()).digest()
    if isinstance(point, int):
        return point.to_bytes(32, 'big')
    if isinstance(point[0], FQ):
        point1 = point[0].n.to_bytes(32, 'big')
        point2 = point[1].n.to_bytes(32, 'big')
        
        return sha256(point1+point2).digest()
    if isinstance(point[0], FQ2):
        point1 = point[0].coeffs[0].n.to_bytes(32, 'big') + point[0].coeffs[1].n.to_bytes(32, 'big')
        point2 = point[1].coeffs[0].n.to_bytes(32, 'big') + point[1].coeffs[1].n.to_bytes(32, 'big')
        return sha256(point1+point2).digest()

def to_challenge(elements):
    _list = [to_binary256(x) for x in elements]
    Cstring = _list[0]
    for i in range(1, len(_list)):
        Cstring += _list[i]
    Chash =  sha256(Cstring).digest()
    return int.from_bytes(Chash, "big", signed=False)

def compute_hash(params, cm):
    (G, o, g1, hs, g2, e) = params
    h = hashG1(to_binary256(cm))
    return h

def ec_sum(list):
    """ sum EC points list """
    ret = None
    if len(list) != 0:
        ret = list[0]
    for i in range(1,len(list)):
        ret = add(ret, list[i])
    return ret

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

def lagrange_basis(indexes, o, x=0):
    """ generates all lagrange basis polynomials """
    l = []
    for i in indexes:
        numerator, denominator = 1, 1
        for j in indexes:
            if j != i:
                numerator = (numerator * (x - j)) % o
                denominator = (denominator * (i - j)) % o
            # if (j > i):
            #     numerator = (j*numerator) % o
            #     denominator = ((j- i)*denominator) % o
            # elif(j < i):
            #     numerator = ((o-j)*numerator) %o
            #     denominator = (denominator * (i - j)) % o
        l.append((numerator * modInverse(denominator, o)) % o)
    return l

def agg_key_sec(params, sk):
    (G, o, g1, hs, g2, e) = params
    # filter missing keys (in the threshold setting)
    filter = [sk[i] for i in range(len(sk)) if sk[i] is not None]
    indexes = [i+1 for i in range(len(sk)) if sk[i] is not None]
    # evaluate all lagrange basis polynomials
    l = lagrange_basis(indexes,o)
    # aggregate keys
    (x, y1, yc) = zip(*filter)
    print()
    print(y1)
    q = len(y1[0])
    aggr_x = 0
    for i in range(len(filter)):
        aggr_x +=((x[i]*l[i])%o)
    aggr_y1 = []
    for i in range(q):
        s1 = 0
        for j in range(len(filter)):
            print(y1[j][i])
            s1 +=((y1[j][i]*l[j])%o)
        aggr_y1.append(s1)
    sk = (aggr_x,aggr_y1,yc[0])
    return sk

def agg_key(params, vks):
    (G, o, g1, hs, g2, e) = params
    # filter missing keys (in the threshold setting)
    filter = [vks[i] for i in range(len(vks)) if vks[i] is not None]
    indexes = [i+1 for i in range(len(vks)) if vks[i] is not None]
    # evaluate all lagrange basis polynomials
    l = lagrange_basis(indexes,o)
    # aggregate keys
    (_, alpha, g1_beta, beta, _) = zip(*filter)
    q = len(beta[0])
    aggr_alpha = ec_sum([multiply(alpha[i], l[i]) for i in range(len(filter))])
    aggr_g1_beta = [ec_sum([multiply(g1_beta[i][j], l[i]) for i in range(len(filter))]) for j in range(q)]
    aggr_beta = [ec_sum([multiply(beta[i][j], l[i]) for i in range(len(filter))]) for j in range(q)]
    aggr_vk = (g2, aggr_alpha, aggr_g1_beta, aggr_beta, filter[0][4])
    return aggr_vk

def make_pi_s(params, commitments, cm, os, r, public_m, private_m, all_attr, prevParams, include_indexes):
    """ prove correctness of ciphertext and cm """
    (G, o, g1, hs, g2, e) = params
    attributes = private_m + public_m

    assert len(commitments) == len(os) and len(commitments) == len(private_m)
    assert len(attributes) <= len(hs)
    # create the witnesses
    wr =random.randint(2, o)
    wos = [random.randint(2, o) for _ in os]
    total_wm = [[random.randint(2, o) for _ in range(len(all_attr[i]))] for i in range(len(all_attr))]
    wm = []
    for i in range(len(all_attr)):
        for j in range(len(all_attr[i])):
            if include_indexes[i][j] == 1:
                wm.append(int(total_wm[i][j]))
    pub_wm = []
    for _ in public_m:
        pub_wm.append(random.randint(2,o))
    wm = wm + pub_wm
    total_wm.append(pub_wm)
    for i in range(1, len(total_wm)-1):
        total_wm[i][0] = total_wm[0][0]
    # compute h
    h = hashG1(to_binary256(cm))
    # compute the witnesses commitments
    Aw = [add(multiply(g1, wos[i]), multiply(h, wm[i])) for i in range(len(private_m))]
    Bw = add(multiply(g1, wr), ec_sum([multiply(hs[i], wm[i]) for i in range(len(attributes))]))
    Cw = []
    for i in range(len(total_wm) - 1):
        (_, ttp_g, _, ttp_hs) = prevParams[i]
        tmp = multiply(ttp_g, total_wm[i][-1])
        for j in range(len(total_wm[i]) - 1):
            tmp = add(tmp, multiply(ttp_hs[j], total_wm[i][j]))
        Cw.append(tmp)
    # create the challenge
    # print("this")
    # print(g1)
    # print(g2)
    # print(cm)
    # print(h)
    # print(Aw)
    # print(Bw)
    # print(Cw)
    # print(hs)
    c = to_challenge([g1, g2, cm, h, Bw]+hs+Aw+Cw)
    # create responses
    rr = (wr - c * r) % o
    ros = [(wos[i] - c*os[i]) % o for i in range(len(wos))]
    total_rm = [[(total_wm[i][j] - c*all_attr[i][j]) % o for j in range(len(total_wm[i]))] for i in range(len(total_wm) - 1)]
    total_rm.append([(total_wm[-1][i] - c*public_m[i]) % o for i in range(len(total_wm[-1]))])
    # rm = [(wm[i] - c*attributes[i]) % o for i in range(len(wm))]
    return (c, rr, ros, total_rm)

def verify_pi_s(params, commitments, cm, prevParams, prevVcerts, proof):
    """ verify correctness of ciphertext and cm """
    (G, o, g1, hs, g2, e) = params

    (c, rr, ros, total_rm) = proof
    for i in range(1, len(total_rm)-1):
        if total_rm[0][0] != total_rm[i][0]:
            return False
    rm = []
    for i in range(len(total_rm)):
        for j in range(len(total_rm[i])):
            if include_indexes[i][j] == 1:
                rm.append(int(total_rm[i][j]))
    rm = rm + total_rm[-1]

    assert len(commitments) == len(ros)
    # re-compute h
    h = hashG1(to_binary256(cm))
    # re-compute witnesses commitments
    Aw = [add(multiply(commitments[i], c), add(multiply(g1, ros[i]), multiply(h, rm[i])))for i in range(len(commitments))]
    Bw = add(multiply(cm, c), add(multiply(g1, rr), ec_sum([multiply(hs[i], rm[i]) for i in range(len(rm))])))
    Cw = []
    for i in range(len(total_rm) - 1):
        _, ttp_g, _, ttp_hs = prevParams[i]
        tmp = multiply(ttp_g, total_rm[i][-1])
        for j in range(len(total_rm[i])-1):
            tmp = add(tmp, multiply(ttp_hs[j], total_rm[i][j]))
        tmp = add(tmp, multiply(prevVcerts[i][0], c))
        Cw.append(tmp)
    return c == to_challenge([g1, g2, cm, h, Bw]+hs+Aw+Cw)

def make_pi_o(params, cm, C, r, s, aggr_vk, opk):
    (G, o, g1, hs, g2, e) = params

    # assert len(ciphertext) == len(k) and len(ciphertext) == len(private_m)
    # assert len(ciphershares) == len(opk)
    # assert len(attributes) <= len(hs)
    # create the witnesses

    wr = [random.randint(2, o) for _ in r]
    ws = [[random.randint(2, o) for _ in s[i]] for i in range(len(s))]
    # compute h
    h = hashG1(to_binary256(cm))
    _, _, _, beta,_ = aggr_vk
    # compute the witnesses commitments
    Aw = [multiply(g2, wri) for wri in wr]
    Bw = [add(multiply(opk[i], wr[i]), ec_sum([multiply(beta[j], ws[i][j]) for j in range(len(ws[i]))])) for i in range(len(ws))]

    # create the challenge
    c = []
    for i in range(len(wr)):
        c.append(to_challenge([g1, g2, h, Aw[i], Bw[i]]+ hs))

    rr = [(wr[i] - c[i]*r[i]) % o for i in range(len(wr))] 
    rs = [[(ws[i][j] - c[i]*s[i][j])% o for j in range(len(s[i]))] for i in range(len(s))]
    return (Aw, Bw, (c, rr, rs))

def verify_pi_o(params, commitments, C, cm, hidden_P, h_r, b_o, aggr_vk, opk, proof):
    (G, o, g1, hs, g2, e) = params
    c, rr, rs = proof
    assert len(C) == len(rr)
    # re-compute h
    h = hashG1(to_binary256(cm))
    # re-compute witnesses commitments
    _, _, _, beta,_ = aggr_vk
    # compute the witnesses commitments
    sum_b_o = ec_sum(b_o)
    for i in range(len(rr)):
        Aw = add(multiply(g2, rr[i]), multiply(C[i][0], c[i]))
        Bw = [add(multiply(C[i][1], c[i]), add(multiply(opk[i], rr[i]), ec_sum([multiply(beta[j], rs[i][j]) for j in range(len(rs[i]))]))) for i in range(len(rr))]
        if not (c[i] == to_challenge([g1, g2, h, Aw, Bw]+ hs)):
            return False
        lhs = e(C[i][1], h) * e(sum_b_o, g1)
        rhs = e(opk[i], h_r[i])
        for j in range(0, len(commitments)):
            tmp = commitments[j] + ec_sum([hidden_P[j][l-1] * (Bn(i+1) ** l) for l in range(1, 1+len(hidden_P[j]))])
            rhs = rhs * e(tmp, beta[j])
        if lhs != rhs:
            return False 
    return True

def VerifyRevokeCred(kr,W,H,S,cm, delta, pub_key, aggre):
    (_, alpha, _,g2_beta, YC) = aggre
    kr_g2 = multiply(G2,kr)
    a = add(kr_g2, pub_key)
    c = pairing(G2, delta) == pairing(a, W)
    print("c")
    print(c)
    f = pairing(alpha, H)
    for i in range(len(cm)):
        f = f * pairing(g2_beta[i], cm[i])
    f = f*pairing(YC, multiply(H,kr))

    v = pairing(G2, S) == f
    return v and c

def PrepareCredRequest(params, aggr_vk, to, no, opk, prevParams, all_attr, include_indexes, public_m=[]):
    private_m = []
    for i in range(len(all_attr)):
        for j in range(len(all_attr[i])):
            if include_indexes[i][j] == 1:
                private_m.append(int(all_attr[i][j]))

    assert len(private_m) > 0
    (G, o, g1, hs, g2, e) = params
    attributes = private_m + public_m
    assert len(attributes) <= len(hs)
    # build commitment
    rand = random.randint(2, o)#generates random number 
    cm = add(multiply(g1, rand), ec_sum([multiply(hs[i], attributes[i]) for i in range(len(attributes))]))
    # build El Gamal encryption
    h = hashG1(to_binary256(cm))
    os = [random.randint(2, o) for _ in range(len(private_m))]#os is a "private_m" length random number array
    commitments = [add(multiply(g1, os[i]), multiply(h, private_m[i])) for i in range(len(private_m))]
    pi_s = make_pi_s(params, commitments, cm, os, rand, public_m, private_m, all_attr, prevParams, include_indexes)
    # build proofs
    # pi_s = make_pi_s(params, gamma, c, cm, k, r, public_m, private_m)
    # Lambda = (cm, c, pi_s)
    # opening information
    # generate polynomials to hide private attributes (m polynomials of degree 'to')
    P = [[random.randint(2, o) for _ in range(0, to)] for _ in range(len(private_m))]
    for i in range(len(private_m)):
        P[i][0] = private_m[i]  
    #generate shares s[i] contains shares to ne shared with opener 'i'
    s = [[poly_eval(Pj,i) % o for Pj in P] for i in range(1,no+1)]
    hidden_P = [[multiply(h, P[i][j]) for j in range(1, to)] for i in range(len(private_m))]

    _, _, _, beta,_ = aggr_vk
    r = [random.randint(2, o) for _ in range(no)]
    C = [(multiply(g2, r[i]), (add(multiply(opk[i], r[i]), ec_sum([multiply(beta[j], s[i][j]) for j in range(len(private_m))])))) for i in range(no)]
    Aw, Bw, pi_o = make_pi_o(params, cm, C, r, s, aggr_vk, opk)
    
    h_r = [multiply(h, ri) for ri in r]
    b_o = [multiply(beta[i], os[i]) for i in range(len(os))] 

    Lambda = (cm, commitments, pi_s, hidden_P, C, pi_o, Aw, Bw, h_r, b_o)
    return Lambda, os


def BlindSign(params, sk, prevParams, prevVcerts, all_pks, Lambda, public_m=[]):
    (G, o, g1, hs, g2, e) = params
    (x, y) = sk
    for i in range(len(prevVcerts)):
        if not VerifyVcerts(prevParams[i], all_pks[i], prevVcerts[i][1], SHA256(prevVcerts[i][0])):
            return None
    (cm, commitments, pi_s, hidden_P, C, pi_o, Aw, Bw, h_r, b_o) = Lambda
    assert (len(commitments)+len(public_m)) <= len(hs)
    # verify proof of correctness
    assert verify_pi_s(params, commitments, cm, prevParams, prevVcerts, pi_s)
    #work from here in thr afternoon.
    assert verify_pi_o(params, commitments, C, cm, hidden_P, h_r, b_o, aggr_vk, opk, pi_o)
    # issue signature
    h = hashG1(to_binary256(cm))
    t1 = [multiply(h, mi) for mi in public_m]
    t2 = add(multiply(h, x), ec_sum([multiply(bi, yi) for yi,bi in zip(y, commitments+t1)]))
    sigma_tilde = (h, t2)
    return sigma_tilde

def BlindSignAttr(params, sk, kr, Lambda, public_m=[]):
    (G, o, g1, hs, g2, e) = params
    (x, y, yc) = sk
    (cm, commitments) = Lambda
    assert (len(commitments)+len(public_m)) <= len(hs)
    # verify proof of correctness
    # assert verify_pi_s(params, commitments, cm, all_vcerts, pi_s)
    #work from here in thr afternoon.
    # assert verify_pi_o(params, commitments, C, cm, hidden_P, h_r, b_o, aggr_vk, opk, pi_o)
    # issue signature
    print("This is Blind sign")
    print("kr")
    print(kr)
    h = hashG1(to_binary256(cm))
    t1 = [multiply(h, mi) for mi in public_m]
    t2 = add(multiply(h, x), ec_sum([multiply(bi, yi) for yi,bi in zip(y, commitments+t1)]))
    ans = (yc*kr)%o
    t2 = add(t2, multiply(h,ans))
    sigma_tilde = (h, t2)
    print("blind sig")
    print(sigma_tilde)
    return sigma_tilde

def elgamal_keygen(params):
   """ generate an El Gamal key pair """
   (G, o, g1, hs, g2, e) = params
   d = random.randint(2, o)
   gamma = multiply(g1, d)
   return (d, gamma)

def elgamal_enc(params, gamma, m, h):
    """ encrypts the values of a message (h^m) """
    (G, o, g1, hs, g2, e) = params
    k = random.randint(2, o)
    a = multiply(g1, k)
    b = add(multiply(gamma, k), multiply(h, m))
    return (a, b, k)

def elgamal_dec(params, d, c):
    """ decrypts the message (h^m) """
    (G, o, g1, hs, g2, e) = params
    (a, b) = c
    return add(b, neg(multiply(a, d)))

def Unblind(params, aggr_vk, sigma_tilde, os):
    _, _, g1_beta, _, _ = aggr_vk
    (h, c_tilde) = sigma_tilde
    print("os")
    print(os)
    sigma = (h, add(c_tilde, neg(ec_sum([multiply(g1_beta[j], os[j]) for j in range(len(os))]))))
    return sigma


def AggCred(params, sigs):
    (G, o, g1, hs, g2, e) = params
    # filter missing credentials (in the threshold setting)
    filter = [sigs[i] for i in range(len(sigs)) if sigs[i] is not None]
    indexes = [i+1 for i in range(len(sigs)) if sigs[i] is not None]
    # evaluate all lagrange basis polynomials
    l = lagrange_basis(indexes,o)
    # aggregate sigature
    (h, s) = zip(*filter)
    aggr_s = ec_sum([multiply(s[i], l[i]) for i in range(len(filter))])
    aggr_sigma = (h[0], aggr_s)
    return aggr_sigma

def make_pi_v(params, aggr_vk, sigma, private_m, disclose_index, disclose_attr, disclose_attr_enc, kappa, public_m, t,kr):
    """ prove correctness of kappa and nu """
    (G, o, g1, hs, g2, e) = params
    (g2, alpha, _, beta, ycG) = aggr_vk
    (h, s) = sigma
    # create the witnesses
    wm = [random.randint(2, o) for i in range(len(private_m))]
    wt = random.randint(2, o)
    wkr = random.randint(2,o)
    # compute the witnesses commitments
    Aw = add(add(multiply(g2, wt), alpha), ec_sum([multiply(beta[i], wm[i]) for i in range(len(private_m)) if disclose_index[i]!=1]))
    Aw = add(Aw,multiply(ycG,wkr))
    Bw = multiply(h, wt)
    # create the challenge
    _timestamp = int(time.time())
    c = to_challenge([g1, g2, alpha, Aw, Bw, kappa]+ hs + beta + encode_attributes(disclose_attr, disclose_attr_enc) + [_timestamp])
    # create responses
    rm = [(wm[i] - c*int(private_m[i])) % o for i in range(len(private_m)) if disclose_index[i]!=1]
    rt = (wt - c*t) % o
    rkr = (wkr - c*kr)%o
    return (Aw, _timestamp, (c, rm, rt,rkr))

def ProveCred(params, aggr_vk, sigma, private_m, disclose_index, disclose_attr, disclose_attr_enc, public_m,acc_pub, pp,kr, W):
    assert len(private_m) > 0
    (G, o, g1, hs, g2, e) = params
    (g2, alpha, _, beta,ycG) = aggr_vk
    (h, s) = sigma
    assert len(private_m) <= len(beta)
    r_prime = random.randint(2, o)
    print("r_prime")
    print(r_prime)
    (h_prime , s_prime) = (multiply(h, r_prime), multiply(s, r_prime))
    sigma_prime =(h_prime, s_prime)
    print("sigma_prime")
    r = random.randint(2, o)
    print("r")
    print(r)
    kappa = ec_sum([multiply(g2, r), alpha, ec_sum([multiply(beta[i], int(private_m[i])) for i in range(len(private_m))]), multiply(ycG,kr)])
    nu = multiply(h_prime, r)
    print("kappa")
    print(kappa)
    print("nu")
    print(nu)
    Aw, timestamp, pi_v = make_pi_v(params, aggr_vk, sigma_prime, private_m, disclose_index, disclose_attr, disclose_attr_enc, kappa, public_m, r,kr)
    Theta = (kappa, nu, sigma_prime, pi_v, Aw, timestamp)

    aggr = None
    if len(public_m) != 0:
        aggr = ec_sum([multiply(beta[i+len(private_m)], public_m[i]) for i in range(len(public_m))])
    
    pi_c = generate_pi_c(pp, acc_pub,kr,W)

    return (pi_c,Theta, aggr)

def generate_pi_c(pp,pb,kr,W):
    
    (g1,g2,g,h2) = pp
    print("g1")
    print(g1)
    print("g2")
    print(g2)
    print("g")
    print(g)
    print("h2")
    print(h2)
    r = genRandom()
    print("r")
    print(r)
    tau1 = genRandom()
    print("tau1")
    print(tau1)
    tau2 = genRandom()
    print("tau2")
    print(tau2)
    print("kr")
    print(kr)
    commit = add(multiply(h2, r), multiply(g2, kr))
    print("commit")
    print(commit)
    C_I = add(commit, pb)
    print("C_I")
    print(C_I)
    delta_1 = (tau1*r)%curve_order
    delta_2 = (tau2*r)%curve_order

    print("delta_1")
    print(delta_1)
    print("delta_2")
    print(delta_2)
    pie_I_1 = add(multiply(g1,tau1), multiply(g, tau2))
    print("pie_I_1")
    print(pie_I_1)
    pie_I_2 = add(W, multiply(g,tau1))
    print("pie_I_2")
    print(pie_I_2)
    r_r = random.randint(2, curve_order)
    print("r_r")
    print(r_r)
    r_tau_1 = random.randint(2, curve_order)
    print("r_tau_1")
    print(r_tau_1)
    r_tau_2 = random.randint(2, curve_order)
    print("r_tau_2")
    print(r_tau_2)
    r_delta_1 = random.randint(2, curve_order)
    print("r_delta_1")
    print(r_delta_1)
    r_delta_2 = random.randint(2, curve_order)
    print("r_delta_2")
    print(r_delta_2)
    R1 = add(multiply(g1, r_tau_1), multiply(g,r_tau_2))
    print("R1")
    print(R1)
    R2 = add(add(multiply(pie_I_1, r_r),multiply(g1, (r_delta_1*(-1))%curve_order)),multiply(g, (r_delta_2*(-1))%curve_order))
    print("R2")
    print(R2)
    R3 = (pairing(C_I, multiply(g, r_tau_1))) * (pairing(h2, multiply(g,(-1*r_delta_1)%curve_order))) * (pairing(h2, multiply(pie_I_2, r_r)))
    print("R3")
    print(R3)
    c = to_challenge([g1,g2,g,h2, commit])
    print("c")
    print(c)
    s_r = (r_r + (c*r))%curve_order
    print("s_r")
    print(s_r)
    s_tau_1 = (r_tau_1 + (c*tau1))%curve_order
    print("s_tau_1")
    print(s_tau_1)
    s_tau_2 = (r_tau_2 + (c*tau2))%curve_order
    print("s_tau_2")
    print(s_tau_2)
    s_delta_1 = (r_delta_1 + (c*delta_1))%curve_order
    print("s_delta_1")
    print(s_delta_1)
    s_delta_2 = (r_delta_2 + (c*delta_2))%curve_order
    print("s_delta_2")
    print(s_delta_2)

    return (commit, pie_I_1, pie_I_2, R1, R2, R3, s_r,s_tau_1, s_tau_2, s_delta_1, s_delta_2)

def verify_pi_v(params, aggr_vk, sigma, kappa, nu, proof, disclose_index, disclose_attr, timestamp):
    (G, o, g1, hs, g2, e) = params
    (g2, alpha, _, beta,ycg) = aggr_vk
    (h, s) = sigma
    (c, rm, rt, rkr) = proof
    # re-compute witnesses commitments
    new_kappa = kappa
    # encoded_disclosed_attr = encode_attributes(disclose_attr, disclose_attr_enc)
    k = 0
    for i in range(len(disclose_index)):
        if disclose_index[i] == 1:
            new_kappa = add(new_kappa, neg(multiply(beta[i], disclose_attr[k])))
            k += 1
    k = 0
    undisclosed_sum = None
    for i in range(len(disclose_index)):
        if disclose_index[i] == 0:
            undisclosed_sum = add(undisclosed_sum, multiply(beta[i], rm[k]))
            k += 1
    undisclosed_sum = add(undisclosed_sum,multiply(ycg, rkr))
    Aw = add(add(multiply(new_kappa, c), multiply(g2, rt)), add(multiply(alpha, (o - c + 1)%o), undisclosed_sum))
    Bw = add(multiply(nu, c), multiply(h, rt))

    # compute the challenge prime
    return c == to_challenge([g1, g2, alpha, Aw, Bw, kappa]+ hs + beta + disclose_attr + [timestamp])

def VerifyCred(params, aggr_vk, Theta, disclose_index, disclose_attr, public_m, pi_c, pp, pb, delta):
    (G, o, g1, hs, g2, e) = params
    (g2, _, _, beta,_) = aggr_vk
    (kappa, nu, sigma, pi_v, _, timestamp) = Theta
    (h, s) = sigma
    assert len(public_m)+len(disclose_index) <= len(beta)
    # verify proof of correctness

    assert verify_pi_v(params, aggr_vk, sigma, kappa, nu, pi_v, disclose_index, disclose_attr, timestamp)
    # add clear text messages
    aggr = None
    if len(public_m) != 0:
        aggr = ec_sum([multiply(beta[i+len(disclose_index)], public_m[i]) for i in range(len(public_m))])
    
    ans = verify_pi_c(pi_c, pp, pb, delta)
    return not is_inf(h) and e(add(kappa, aggr), h) == e(g2, add(s, nu)) and ans

def verify_pi_c(pi_c, pp, pb, delta):
    (commit, pie_I_1, pie_I_2, R1, R2, R3, s_r,s_tau_1, s_tau_2, s_delta_1, s_delta_2) = pi_c
    (g1, g2,g,h2) = pp
    print("pp")
    print(pp)
    print("pb")
    print(pb)
    C_I = add(commit, pb)
    print("C_I")
    print(C_I)
    c = to_challenge([g1,g2,g,h2, commit])
    ans1 = add(add(multiply(pie_I_1, (c*(-1))%curve_order), multiply(g1, s_tau_1)), multiply(g,s_tau_2))
    ans2 = add(add(multiply(pie_I_1, s_r), multiply(g1, (s_delta_1*(-1))%curve_order)), multiply(g,(s_delta_2*(-1))%curve_order))
    ans3 = R3 * (pairing(C_I, multiply(pie_I_2,c)))
    ans4 = (pairing(C_I,multiply(g, s_tau_1))) * (pairing(h2, multiply(g, ((-1)*s_delta_1)%curve_order))) *(pairing(h2,multiply(pie_I_2, s_r))) * (pairing(g2, multiply(delta, c)))

    print("R1")
    print(R1)
    print("ans1")
    print(ans1)
    print("R2")
    print(R2)
    print("ans2")
    print(ans2)
    print("ans3")
    print(ans3)
    print("ans4")
    print(ans4)

    return (R1 == ans1) and (R2 == ans2) and (ans3 == ans4)
#deprecated
def open_keygen(params, no, to):
    assert no >= to and to > 0
    (G, o, g1, hs, g2, e) = params
    z = [random.randint(2, o) for _ in range(no)]
    f = [multiply(g2, zi) for zi in z]
    reg = {}
    for i in range(1, no+1):
        reg.setdefault(i, {})
    return (z, f, reg)

def gen_beaver_keys(params, no):
    (_, o, _, _, g2, _) = params
    priv = []
    public =[]
    for i in range(no):
        z = random.randint(2, o)
        f = multiply(G1, z)
        priv.append(z)
        public.append(f)
    return (public, priv)

def opener_keygen(params, no):
    (_, o, _, _, g2, _) = params
    priv = []
    public =[]
    for i in range(no):
        z = random.randint(2, o)
        f = multiply(g2, z)
        priv.append(z)
        public.append(f)
    return (public, priv)



def open_cred(params, rand_sig, T, reg, opener_, indexes, no, to, aggr_vk):
    (G, o, g1, hs, g2, e) = params
    _, alpha, _, beta, _ = aggr_vk 
    h_prime, s_prime = rand_sig
    # T = {}
    # for opener in range(1, no+1):
    #     for h in reg[opener].keys():
    #         T.setdefault(h, {})
    #         T[h].setdefault(opener, e(h_prime, reg[opener][h][0]))
    # indexes = sample(range(1,no+1), 1+to)

    assert len(indexes) > to

    l = lagrange_basis(indexes, o)

    #assume all registries are upto date
    for h in reg.keys():
        flag = 0
        share = T[h][indexes[0]] ** l[0]
        count = 1
        for i in range(1, len(indexes)):
            try:
                share *= T[h][indexes[i]] ** l[i]
            except:
                flag = 1
            count += 1
        if count < to +1:
            continue
        a = e(h_prime, alpha) * share * e(h_prime, reg[h][1])
        b = e(s_prime, g2)
        if a == b:
            return h
    return None

def calculate_T(params, rand_sig, reg, no):
    (G, o, g1, hs, g2, e) = params
    h_prime, s_prime = rand_sig
    T = {}
    for opener in range(1, no+1):
        for h in reg[opener].keys():
            T.setdefault(h, {})
            T[h].setdefault(opener, e(reg[opener][h][0], h_prime))
    return T

def open_cred(params, rand_sig, T, reg, opener_, indexes, no, to, aggr_vk):
    (G, o, g1, hs, g2, e) = params
    _, alpha, _, beta,_ = aggr_vk 
    h_prime, s_prime = rand_sig

    assert len(indexes) > to

    l = lagrange_basis(indexes, o)

    #assume all registries are upto date
    for h in reg.keys():
        flag = 0
        share = T[h][indexes[0]] ** l[0]
        count = 1
        for i in range(1, len(indexes)):
            try:
                share *= T[h][indexes[i]] ** l[i]
            except:
                flag = 1
            count += 1
        if count < to +1:
            continue
        a = e(alpha, h_prime) * share * e(reg[h][1], h_prime)
        b = e(g2, s_prime)
        if a == b:
            return h
    return None

def verify_disclosure(params, commit, disclosed_attr, disclose_index, encode_str, ZKPoK):
    (G, o, g1, hs, g2, e) = params
    filter_encode_str = []
    for i in range(len(disclose_index)):
        if disclose_index[i] == 1:
            filter_encode_str = encode_str[i]
    encoded_disclosed_attr = encode_attributes(disclosed_attr, filter_encode_str)
    tmp = None
    for i in range(len(hs)):
        if disclose_index[i] == 1:
            tmp = add(tmp, multiply(hs[i], encoded_disclosed_attr[i]))
    tmp = add(commit, neg(tmp))
    (c, rr, rm) = ZKPoK
    Aw = multiply(g2, rr)
    j = 0
    for i in range(len(hs)):
        if disclose_index[i] != 1:
            Aw = add(Aw, multiply(hs[i], rm[j]))
            j += 1
    Aw = add(Aw, multiply(tmp, c))
    element_list = [g1, g2, Aw, commit] + hs + disclosed_attr
    return (c == to_challenge(element_list))

def PreOpening(params, Registry, sigma):
    (_, _, _, _, _, e) = params
    send_open_shares = []
    shareRegistry = {}
    for issuing_session_id in Registry.keys():
        shareRegistry.setdefault(issuing_session_id, e(Registry[issuing_session_id]["private-share"], sigma[0]))
    return shareRegistry

def OpenCred(params, ret_shares, indexes, sigma, to, Reg, aggr_vk):
    (G, o, g1, hs, g2, e) = params
    _, alpha, _, _,_ = aggr_vk
    assert len(indexes) >= to , "Opening threshold criteria does not met."
    l = lagrange_basis(indexes, o)
    h_prime, s_prime = sigma

    for issuing_session_id in Reg.keys():
        share = ret_shares[indexes[0]][issuing_session_id] ** l[0]
        for i in range(1, len(indexes)):
            share *= ((ret_shares[indexes[i]][issuing_session_id]) ** l[i])
        a = e(alpha, h_prime) * share * e(Reg[issuing_session_id]["public-share"], h_prime)
        b = e(g2, s_prime)
        if a == b:
            return issuing_session_id
    return None