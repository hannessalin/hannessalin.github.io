import sys
sys.path.insert(1,'/Users/hannessalin/Development/mcl-python/mcl-python')
import mcl

from mcl import GT
from mcl import G2
from mcl import G1
from mcl import Fr
from mcl import Fp

import time

def rsa_acc_add(x,z):
    return z * x

def bp_acc_add(x,s,z):
    return z * (x+s)

def rsa_acc_del(x,z):
    return z * ~x

def bp_acc_del(x,s,z):
    return z * ~(x+s)

def rsa_extract_witness(x,z):
    return rsa_acc_del(x,z)

def bp_extract_witness(x,s,z2):
    return bp_acc_del(x,s,z2)

def rsa_verify(x,w,z):
    if rsa_acc_add(x,w) == z:
        return 1
    return 0

def bp_verify(x,s,g1,g2,w,z):
    v_res_left = GT.pairing(g1 * (x+s), w)
    v_res_right = GT.pairing(z, g2)
    if v_res_left == v_res_right:
            return 1
    return 0

def bls_sign(sk,m):
    sig = G1.hashAndMapTo(m)
    return (sig * sk)

def bls_verify(sigma,m,g2, pk):
    v_left = GT.pairing(sigma, g2)
    v_right = GT.pairing(G1.hashAndMapTo(m), pk)
    if v_left == v_right:
        return 1
    return 0

def dh_key_exchange(lst):
        return 0

G1_STR = b"1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569"
G2_STR = b"1 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582"

s = Fr()
x1 = Fr()
x2 = Fr()
x1inv = Fr()
keys = Fr()
s.setByCSPRNG()
x1.setByCSPRNG()
x2.setByCSPRNG()
keys.setByCSPRNG()

g1 = G1()
g1bp = G1()
g1.setStr(G1_STR)
g1bp.setStr(G1_STR)
g2 = G2()
g2.setStr(G2_STR)
z1 = g1
z2bp = g2
z1bp = g1

print("TESTING RSA ACCUMULATOR..")
print("=========================")
print("acc is now: ",z1.getStr())
print("accumulating ",x1.getStr())
z1 = rsa_acc_add(x1,z1)
print("acc is now: ",z1.getStr())
print("deleting ",x1.getStr())
z1 = rsa_acc_del(x1,z1)
print("acc is now: ",z1.getStr())
print("accumulating ",x1.getStr())
print("accumulating ",x2.getStr())
z1 = rsa_acc_add(x1,z1)
z1 = rsa_acc_add(x2,z1)
print("extract witness for ",x1.getStr())
w1 = rsa_extract_witness(x1,z1)
print("witness is ",w1.getStr())
print("prove membership for ",x1.getStr())
c = rsa_verify(x1,w1,z1)
print("verification status: ",c)
print("")
print("")
print("")
print("TESTING PAIRING ACCUMULATOR..")
print("=============================")
print("acc is now: ",z1bp.getStr())
print("accumulating: ",x1.getStr())
z1bp = bp_acc_add(x1,s,z1bp)
z2bp = bp_acc_add(x1,s,z2bp)
print("acc is now: ",z1bp.getStr())
print("deleting ",x1.getStr())
z1bp = bp_acc_del(x1,s,z1bp)
z2bp = bp_acc_del(x1,s,z2bp)
print("acc is now: ",z1bp.getStr())
print("accumulating ",x1.getStr())
print("accumulating ",x2.getStr())
z1bp = bp_acc_add(x1,s,z1bp)
z1bp = bp_acc_add(x2,s,z1bp)
z2bp = bp_acc_add(x1,s,z2bp)
z2bp = bp_acc_add(x2,s,z2bp)
print("extract witness for ",x1.getStr())
w1bp = bp_extract_witness(x1,s,z2bp)
print("witness is ",w1bp.getStr())
print("prove membership for ",x1.getStr())
cbp = bp_verify(x1,s,g1,g2,w1bp,z1bp)
print("verification status: ",cbp)


time_bls_start = time.time()
bls_sign(s, message)
time_bls_stop = time.time()
print("BLS signing: ", f'{(time_bls_stop-time_bls_start):.10f}')

time_enc_start = time.time()
enc_keys = (g1 * keys) * x1
time_enc_stop = time.time()
print("Enc : ", f'{(time_enc_stop-time_enc_start):.10f}')

g3 = g1
time_enc_start = time.time()
g3 = G1.hashAndMapTo(b"abcd")
time_enc_stop = time.time()
print("Hash : ", f'{(time_enc_stop-time_enc_start):.10f}')

s3 = s
time_enc_start = time.time()
s3.setByCSPRNG()
time_enc_stop = time.time()
print("PRNG : ", f'{(time_enc_stop-time_enc_start):.10f}')

print("")
print("TIME PERFORMANCE")
print("================")
d=10
e=10
t_rsa_acc_1 = time.time()
for _ in range(0,d):
    z1 = rsa_acc_add(x1,z1)
t_rsa_acc_2 = time.time()
t_rsa_acc_diff = t_rsa_acc_2 - t_rsa_acc_1
print("RSA accumulation time: ",f'{(t_rsa_acc_diff/e):.10f}')

t_rsa_del_1 = time.time()
for _ in range(0,d):
    z1 = rsa_acc_del(x1,z1)
t_rsa_del_2 = time.time()
t_rsa_del_diff = t_rsa_del_2 - t_rsa_del_1
print("RSA deletion time: ",f'{(t_rsa_del_diff/e):.10f}')

z1 = rsa_acc_add(x1, z1)
t_rsa_w_1 = time.time()
for _ in range(0,d):
    w1 = rsa_extract_witness(x1, z1)
t_rsa_w_2 = time.time()
t_rsa_w_diff = t_rsa_w_2 - t_rsa_w_1
print("RSA witness extraction time: ",f'{(t_rsa_w_diff/e):.10f}')

t_rsa_p_1 = time.time()
for _ in range(0,d):
    c = rsa_verify(x1, w1, z1)
t_rsa_p_2 = time.time()
t_rsa_p_diff = t_rsa_p_2 - t_rsa_p_1
print("RSA verification time: ",f'{(t_rsa_p_diff/e):.10f}')

print("")

t_bp_p_1 = time.time()
for _ in range(0,d):
    cbp = bp_verify(x1, s, g1, g2, w1bp, z1bp)
t_bp_p_2 = time.time()
t_bp_p_diff = t_bp_p_2 - t_bp_p_1
print("Pairing verification time: ",f'{(t_bp_p_diff/e):.10f}')
