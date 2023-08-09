import json
from web3 import Web3
import os
from crypto import *
import pickle
import jsonpickle
from utils import *
def decodetoG1(l):
    return (FQ(l[0]), FQ(l[1]))
def decodeToGT(encoded_g2):
        return FQ12([encoded_g2[0], encoded_g2[1],encoded_g2[2],encoded_g2[3],
	       		encoded_g2[4], encoded_g2[5],encoded_g2[6],encoded_g2[7],
				encoded_g2[8], encoded_g2[9],encoded_g2[10],encoded_g2[11]])
def decodeToG2(encoded_g2):
	return (FQ2([encoded_g2[0][0], encoded_g2[0][1]]), FQ2([encoded_g2[1][0], encoded_g2[1][1]]))
g1 = (1, 2)
g1 = decodetoG1(g1)
g = (3034357128961006585507572168461944180544996089907454518087402632861344881216, 5046932528181050560432695870868936866894170674109011652882369365137625879090)
g = decodetoG1(g)
g_2 = ((10857046999023057135944570762232829481370756359578518086990519993285655852781, 11559732032986387107991004021392285783925812861821192530917403151452391805634), (8495653923123431417604973247489272438418190587263600148770280649306958101930, 4082367875863433681332203403145435568316851327593401208105741076214120093531))
g_2 = decodeToG2(g_2)
print(g_2)
h_2 = ((9582654798852357659970314218512303933783608450011109315483603668504813034723, 17538197290086421814374790501434878032496788376798009378322867189453342450435), (10158144591757546359781713865549099189825881570362176485769297353734426630530, 8237546654491294313014911513333179223433634309783385001689730286185002941451))
h_2 = decodeToG2(h_2)
print(h_2)
r = 14670358178825103598311349569062863296366486383662690248428074071102149310843
pub_key = ((20819370557043781156485500549503588623111449936810220049361320353921082989387, 19870937190318397804187305063298580591253732030204211694659532635436036511459), (15266753157202239207226400961481645057186597259643715964353883051834116235772, 1295400544025594177154219534253726083427071656907899385147597626729133504859))
pub_key = decodeToG2(pub_key)
kr = 14084502241375657429135798806102540212744361023684248798068805057371604897365
W = (1, 2)
W = decodetoG1(W)
commit = add(multiply(h_2,r),multiply(g_2,kr))
print(commit)
com = ((19124294641205038658416152992852181374593122058116800562906641044898585701842, 20539969689513456370363016301644181877933188610949274179998498556408477009947), (16318316155437225591206544776159776042213788460343414665803707062003987364261, 1385879689989365717403376532133505620859403954081077419393122509224935101749))
com = decodeToG2(com)
c_C_I = add(commit, pub_key)
print(c_C_I)
C_I = ((5427036769900055833254425086186694106715930090258632022155213198138670579193, 2264512651484720702195767528448505716479602772735017496412469745981168741007), (5544472676183414616872690924880977950907057671286890910028015460309441539613, 14735001501749684308402992916766960244564929205541308987961748891907779825384))
C_I = decodeToG2(C_I)
tau_1 = 10019882303664422418753303357179820192628185582044978533539991308881357807760
tau_2 = 2046734820650800955935773988753466731203621505263745624849609485119972985120
c_d_1 = tau_1 * r
c_d_2 = tau_2 * r
print(c_d_1)
print(c_d_2)
d_1 = 7661354588107448037840610277044465494868631405501099149199918438242589786527
d_2 = 1485146777747657737601951480229717030677645736379376690461184276437397036788
c_pi_I_1 = add(multiply(g1,tau_1), multiply(g, tau_2))
c_pi_I_2 = add(W, multiply(g,tau_1))
print(c_pi_I_1)
print(c_pi_I_2)
pi_I_1 = (9872744726213587638869344602014810154509409854389487242982897530217760707315, 12913655155427941931739440469572954232692069078116396597322653979275667768785)
pi_I_1 = decodetoG1(pi_I_1)
pi_I_2 = (18735105262001829836992414645081714003315937940925726932688607806066259735970, 12069854945188919853386276494963657019165625956302774690424122260385340618153)
pi_I_2 = decodetoG1(pi_I_2)
r_r = 19522676744909247621732931308010511599323001475813480958200320947960305253934
r_tau_1 = 14814629735227756235157319526487374126662108303272823787245352544016380657584
r_tau_2 = 8896583741214476249912610477668202161351865448045379042263158237133241549237
r_delta_1 = 3574837275215240162858054696352889565108276810281904466184303096905819445213
r_delta_2 = 20498221940090338678338779453584731066615474861901102778863703815438325008404
c_R1 = add(multiply(g1, r_tau_1), multiply(g,r_tau_2))
c_R2 = add(add(multiply(pi_I_1, r_r),multiply(g1, (r_delta_1*(-1))%curve_order)),multiply(g, (r_delta_2*(-1))%curve_order)) 
c_R3 = (pairing(C_I, multiply(g, r_tau_1))) * (pairing(h_2, multiply(g,(-1*r_delta_1)%curve_order))) * (pairing(h_2, multiply(pi_I_2, r_r)))
R1 = (18904312477323851646879170484545473806638207241734974257235957921963175841058, 12024601346466097133166248051467316155684190578742321421645480738150971589747)
R1 = decodetoG1(R1)
R2 = (11794505716996659924363328246939012652516651007501095915722903693137115308944, 10459255022279836947956134475447137985156564714743158937621301453213734528252)
R2 = decodetoG1(R2)
R3 = (12364352866320865299036129934290167043403368739011099440798803453345776519081, 3631938441703492981846374878758463140774826020386730212104282732315615972865, 5922460989431900477999544022783204543451665503322210600472547743814006708258, 12561358641588589455034923835786004277446038131321385301087248424383336308274, 10615809880087145602574965527521041396630131183681594652715514423462755838030, 281973751234929086395227903579249643608978180472457188583867951114510884552, 20378581292469997430930410303888147907175685024351068986156453634946070372990, 16595526871885695802521890122617294542235360945249978298505077817633330762842, 18711034825363265315699511660214679689423591010122709391634003629268125524182, 4645327434556986318386692604285963549603312836484861418359280405740908667422, 19383864699119203911095447295356439101089240088476982086918007884466238321170, 13996212276182124201455568344169903042888272625531346646158787922655298830925)
R3 = decodeToGT(R3)
print(c_R1)
print(c_R2)
print(c_R3)
c = to_challenge([g1,g_2,g,h_2, commit])
s_r = (r_r + (c*r))%curve_order
s_tau_1 = (r_tau_1 + (c*tau_1))%curve_order
s_tau_2 = (r_tau_2 + (c*tau_2))%curve_order
s_delta_1 = (r_delta_1 + (c*d_1))%curve_order
s_delta_2 = (r_delta_2 + (c*d_2))%curve_order
print("fghj")
print(s_r)
print(s_tau_1)
print(s_tau_2)
print(s_delta_1)
print(s_delta_2)
print("dfghjkl")
delta = (10011538851896331741718471022130174754035529820773348102887429830406323574874, 17705275207282249891010022188296677046424410810187654207153748541559584424739)
delta = decodetoG1(delta)
ans1 = add(add(multiply(pi_I_1, (c*(-1))%curve_order), multiply(g1, s_tau_1)), multiply(g,s_tau_2))
ans2 = add(add(multiply(pi_I_1, s_r), multiply(g1, (s_delta_1*(-1))%curve_order)), multiply(g,(s_delta_2*(-1))%curve_order))
ans3 = R3 * (pairing(C_I, multiply(pi_I_2,c)))
ans4 = (pairing(C_I,multiply(g, s_tau_1))) * (pairing(h_2, multiply(g, ((-1)*s_delta_1)%curve_order))) *(pairing(h_2,multiply(pi_I_2, s_r))) * (pairing(g_2, multiply(delta, c)))
print(ans1)
print(ans2)
print(ans3)
print(ans4)