
import sys
from sympy import *

sys.path.insert(0, '../../../core')                                                  
from security_analysis_ac17 import *
from trivial_security_and_collusion import analysis_trivial_and_collusion_security
from decryption import DecryptionAttack
from security import *

if __name__ == "__main__":

    # ABGW17 - IBE1 scheme

    alpha, b, bp, b0, b1, r, rp, r0, r1, x, x1, x2, y, s, s1, s2, sp = symbols('alpha, b, bp, b0, b1, r, rp, r0, r1, x, x1, x2, y, s, s1, s2, sp')

    k1 = alpha/(b + x1)
    k2 = alpha/(b + x2)
    c1 = s*(b + y)
    mpk1 = b
    
    # no known values

    unknown = [alpha, b, s]

    k = [k1] 
    c = [c1]
    mpk = [mpk1]
    gp = []

    security_attack = SecurityAttack()
    security_attack.init(alpha*s, k, c, mpk, unknown)
    security_attack.run()
    print("\n[*] Security analysis results:\n")
    print("\n" + security_attack.show_solution())

    """
    ctr = 0
    for kpoly in k:
        k[ctr] = k[ctr].subs(A11,-w2*A12)
        ctr += 1
    
    ctr = 0
    for kpoly in kp:
        kp[ctr] = kp[ctr].subs(A21, -w2p*A22)
        ctr += 1

    # print(kp)
    """


    # """    
    print("\n Decryption attack: \n")
    decryption_attack = DecryptionAttack()                                       
    decryption_attack.init(alpha * s, k, c, mpk, gp, unknown)                      
    decryption_attack.run()                                                      
    msg = decryption_attack.show_solution()         
    print(msg)
    # """
    
