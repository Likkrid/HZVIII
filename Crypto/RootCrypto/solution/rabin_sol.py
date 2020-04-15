#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from Crypto.Util.number import *
from pwn import *
import itertools

def square_root(a, p):
    #Tonelli–Shanks algorithm
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) / 4, p)

    s = p - 1
    e = 0
    while s % 2 == 0:
        s /= 2
        e += 1

    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    x = pow(a, (s + 1) / 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in xrange(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):

    ls = pow(a, (p - 1) / 2, p)
    return -1 if ls == p - 1 else ls

#CRT
# x ≡ ai (mod ni)
def crt(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)

    for n_i, a_i in zip(n, a):
        p = prod / n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod


def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a / b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

def decryption(c, p, q, r):
    output = []
    n = [ p, q, r ]
    m_p, m_q, m_r = 0, 0, 0
    m_p = square_root(c,p)
    m_q = square_root(c,q)
    m_r = square_root(c,r)

    congruence_system = [[m_p,p-m_p], [m_q,q-m_q], [m_r,r-m_r]]
    for i in list(itertools.product(*congruence_system)):
        output.append(long_to_bytes(crt(n, list(i))))
    return output

req = remote('localhost', 6776)

t = False
i = 1
test = []
while not t:
    req.recvuntil(']it')

    req.sendline('n')

    req.recvuntil('encrypt:')

    message = 'test' * i
    req.sendline(message)

    req.recvline()
    req.recvline()

    cipher = req.recvline().strip()

    if bytes_to_long(message)**2 > int(cipher):

        order = i
        test.append({bytes_to_long(message),cipher})
        t = True
    else:
        i += 1

found = False
i = 1
while not found:
    req.recvuntil(']it')

    req.sendline('n')

    req.recvuntil('encrypt:')

    message = 'test' * (order+i)
    req.sendline(message)

    req.recvline()
    req.recvline()

    cipher = req.recvline().strip()
    test.append({bytes_to_long(message),int(cipher)})

    m1,c1 = test[0]
    m2,c2 = test[i]

    modulus = GCD(pow(int(m1), 2) - int(c1), pow(int(m2), 2) - int(c2))
    if (m2**2%modulus) == int(c2) and (int(m1)**2%modulus) == int(c1):
        n = modulus
        found = True
        print ("[*] Modulus recovered : {}").format(str(n))
    i += 1

#modulus = 524401030912935840156368455492538779896072847975492539783953077216160596391396524596555889403478360635508941057096235808098982594382826760788658887864079605086232038075105222664675815063138005147439485782506259009624824296232296944425318333560850178684312526817439342734689738364582211830578544010699057807203320116245103219640909951081494988002319765382671236511814606458624467531074582596773431874694935213863065835130776570102528998539870037798875514772405725953152807827875644835063461362848276235279288494790662427109010174114288547210746780314409433490420740929029917660922177529383005755493606450968989600036591872139774563457291304714621382850306338318383694394023670273738741884285451728722809179581104268263353354410259122126897482066524944828581102573072424747254413355317992820025689435898822618357910829932309681708512761041680580326542636488901596400273092859496536665261209628771967676593298088438756584085850168390826492357591694530728927545159125688421720769504309135232994452965404788824145859903335144277993141641812228988356068335627075992515031511555465443000310271590499571469597897378149382128872926855327643021881658781065609514486670512314081487136875340579717886552369036342643166242383119050497955330177041
#using factorDB
p = 169190849908171023288307339044530660251053691880472974308588587669108393339479218343467606959873557652028796331630894148101895749038501058026903394542693227061956193960988086687175451732633751931097670564771615055986238919767344273578222753486514961292954087400823074165260390884832213999754832198100883152817
q = 109428029649440430724985328440426800088095512795047844765497650150300167758617620285912074886715196546316654722962451425382958488866875211874405557040233022812316149661256784075369885622582466551711782792964231138949677143512586814879652448516728832311262378696530387109817059014697289977596289928808870560521
r = 28324228239363374596194831603892272765727935024801683641238831323425191843497399356113972653282785821445234526607381395724909846914957106058244321651826693574257510573656400163170422624552961721577807397112275802706888482667684303788820139172010927871675237895870362714635301376080466880238223417751435854652464694778418228850337952011455340246224617747303090930130568062616483524260986660013661622929386103302423390900287566404575267019924851268350001130408444267784904813657390464859088902327337540317280115899553958900970608889557148594099762075034121853284539269993839507653071747630042882785844835860744926287513


req.recvuntil(']it')
req.sendline('e')
req.recvuntil('\n')
req.recvuntil('\n')

to_decrypt = int(req.recvline().strip())

plains = decryption(to_decrypt, p, q, r)
for i in plains:
    try:
        i.decode()
        print ("[*] Decrypted string: {}").format(str(i))
        req.sendline(i)
        print req.recvall()
    except:
        pass
