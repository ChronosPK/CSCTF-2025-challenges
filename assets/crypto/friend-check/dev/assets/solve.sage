__import__("os").system("pip install pycryptodome")
from Crypto.Util.number import long_to_bytes

public = 111589618518243065995277577114763849
prime = 20966040210558651765632106472607825931533981371474235227943345243212507
ct = 7268862493461781752603700516437349663415400402628512363313184258690143
friend_powers = [151292854050382116035763063, 24634434134153840231225836923, 350928759816759802286087280, 659233294050679826486565474381, 3800009732327813341886384352, 472444725468225084454100997285844, 2567582852803931729692441828502302]
p2 = 5983008023
a = 0
b = 1
F.<i> = GF(p2^2, modulus=[1,0,1])
E = EllipticCurve(F, [a, b])
P, Q = E.gens()
R = E(4372176737*i + 1948408046, 2141680381*i + 3328801657)
Z = E(5416566873*i + 344136313, 1284413881*i + 1581206776)


mat = []
mat.append([public] + [1] + [0]*(len(friend_powers)))
for i in range(len(friend_powers)):
    mat.append([-friend_powers[i]]+ [0]*(i+1) + [1] + [0]*(len(friend_powers)-i-1))
mat.append([prime] + [0]*(len(friend_powers)+1))
print(mat)

L = matrix(mat)

W = diagonal_matrix([2**1024, 2**1024] + [1] * (len(friend_powers)))
B = (L*W).LLL() / W

print(B)


v = next(v for v in B if v[0]==0 and abs(v[1])==1)
v *= sign(v[1])
print(v)


for i in range(2, len(v)):
    ct *= pow(int(v[i]),-1, prime)
    ct %= prime

ct = int(ct)
print(ct)
print(ct.bit_length())
print(long_to_bytes(ct))


mod_PQ = E.isogeny(P+Q, algorithm='factored')
b = mod_PQ(Z).log(mod_PQ(R))
print(b)

flag = crt([b, ct], [p2, prime])
print(flag)
print(flag.bit_length())
print(long_to_bytes(flag))