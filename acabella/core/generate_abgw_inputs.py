#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022
# 
# This program is free software: you can redistribute it and/or modify  
# it under the terms of the GNU General Public License as published by  
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see <http://www.gnu.org/licenses/>.

"""generate_abgw_inputs.py: This module contains functions involved in the
translation of ACABELLA inputs to the ABGW format.
"""

from common_methods import *
from sympy import *

init_printing(use_unicode=True)


from sympy.printing import ccode
import re
CPOW = re.compile(r'pow\((?P<var>[A-Za-z_]\w*)\s*,\s*2\s*\)')

def to_c_code(expr):
    """
    This functions removes squares in the form x**2 and replace them
    by x*x. This is required in the ABGW tool. This function is
    based on https://stackoverflow.com/questions/14264431/expanding-algebraic-powers-in-python-sympy

    Parameters:
        expr (sp.core.list.Symbol): Sympy expression to transform.
        
    Returns:
        (sp.core.list.Symbol): Transformed Sympy expression.
    """    
    code = ccode(expr)
    # sympy has a hard time unsimplifying x**2 to x*x
    # replace all pow(var,2) with var*var
    code = re.sub(CPOW, r'\g<var>*\g<var>', code)
    return code

# generates an abgw input
def generate_abgw_input(blindingvalue, kenc, cenc, benc, unknown, known):
    """
    This function generates a valid ABGW input given a description of
    the ABE scheme.

    Parameters:
        blindingvalue (sp.core.list.Symbol): Blinding value, by default a*s.
        kenc (list): List of key encodings
        cenc (list): List of ciphertext encodings
        benc (list): List of b encodings
        unknown (unknown): List of unknown values
        known (known): List of known values
    """   
    penc = gen_all_p(kenc, cenc, [], [])
    penc = canonical(penc)
    penc = [to_c_code(i) for i in penc]

    # prepare header

    ## c_i's

    coef = ""
    for ctr2 in range(len(penc)):
        if ctr2 != len(penc)- 1:
            coef += "c" + str(ctr2 + 1) + ","
        else:
            coef += "c" + str(ctr2 + 1) + " in Zp."
    print("\nparams " + coef)

    ## vars

    print("vars ", end="")
    for elem in unknown:
        if elem != unknown[-1]:
            print(str(elem) + ",", end="")
        else:
            print(str(elem) + " in Zp.\n", end="")

    if not known:
        print("\n")

    ## extra params
    
    if known:
        print("params ", end="")
        for elem in known:
            if elem != known[-1]:
                print(str(elem) + ",", end="")
            else:
                print(str(elem) + " in Zp.\n", end="")
        print("\n")

    # prepare constraints

    ctr = 1
    for en in penc:
        if en != penc[-1]:
            print("c" + str(ctr) + "*(" + str(en) + ")" + " +")
        else:
            print("c" + str(ctr) + "*(" + str(en) + ")" + "")
            print("= a * s.\n\ngo.\n")    
        ctr += 1
    
if __name__ == "__main__":

    print("[*] YJR13")

    a, b, bp, r, s, x1, x2 = symbols("a, b, bp, r, s, x1, x2")

    k1 = a * (1 / x1) + x2 * b + r * (b / bp)
    k2 = r * bp * (1 / x1)
    k3 = r * b
    c1 = s
    c2 = s / bp
    mpk1 = bp
    gp1 = b

    # known values by the attacker
    # without the need of corruption

    known1 = x1
    known2 = x2

    k = [k1, k2, k3]
    c = [c1, c2]
    mpk = [mpk1]
    gp = [gp1]
    known = [known1, known2]
    unknown = [a, r, s, b, bp]

    generate_abgw_input(a*s, k, c, gp, unknown, known)
                       

    print("[*] NDCW15")

    a, b1, b2, s, d1, d2, d3 = symbols("a, b1, b2, s, d1, d2, d3")

    gp1 = b1
    gp2 = b2
    gp3 = 1

    k1 = a * (1 / (b1 + d3)) + d2 * b2 * (1 / (b1 + d3))
    k2 = d1
    k3 = d1 * b1
    c1 = s
    c2 = s * b1
    c3 = s * b2

    gp = [gp1, gp2, gp3]
    k = [k1, k2, k3]
    c = [c1, c2, c3]
    mpk = []

    unknown = [a, b1, b2, s]
    known = [d1, d2, d3]

    generate_abgw_input(a*s, k, c, gp, unknown, known)

    
    # Wat11

    print("[*] Wat11")

    alpha, b, bp, b0, b1, b2, r, rp, x, y, s, s1, sp, sp1, sp2 = symbols('alpha, b, bp, b0, b1, b2, r, rp, x, y, s, s1, sp, sp1, sp2')

    k1 = alpha + r*b
    k2 = r*b0
    k3 = r
    c1 = s*b - s1 + sp*b1
    c2 = s
    c3 = sp
    c4 = s1 + sp*b2
    # c5 = sp2
    mpk1 = b0
    mpk2 = b1
    mpk3 = b
    mpk4 = 1
    mpk5 = b2
    
    unknown = [alpha, b, b0, b1, b2, r, s, s1, sp]

    k = [k1, k2, k3]
    c = [c1, c2, c3, c4]
    mpk = [mpk1, mpk2, mpk3, mpk5]

    generate_abgw_input(alpha*s, k, c, mpk, unknown, [])
   
    
    # BSW07

    print("[*] BSW07")

    alpha, b, bp, b0, b1, r, rp, x, y, s, sp = symbols('alpha, b, bp, b0, b1, r, rp, x, y, s, sp')

    # actual encoding
    k1 = (alpha + r)/b
    k2 = r + rp * b0
    k3 = rp
    c1 = s*b
    c2 = s
    c3 = s*b1
    mpk1 = b
    mpk2 = b0
    mpk3 = b1
    mpk4 = 1
    
    # no known values

    unknown = [alpha, b, b0, b1, r, rp, s]

    k = [k1, k2, k3]
    c = [c1, c2, c3]
    mpk = [mpk1, mpk2, mpk3, mpk4]
    gp = []

    generate_abgw_input(alpha * s, k, c, mpk, unknown, [])
    
    print("\n ABGW starts here \n\n")
    
    # ABGW17 - CP-ABE scheme

    alpha, b, bp, b0, b1, r, rp, r0, r1, x1, x2, y, s, s1, s2, sp = symbols('alpha, b, bp, b0, b1, r, rp, r0, r1, x1, x2, y, s, s1, s2, sp')
    A11, A12, A21, A22 = symbols('A11, A12, A21, A22')
    a, z1, z2, z3, z4 = symbols('a, z1, z2, z3, z4')

    # actual encoding
    k1 = a + r*b
    k2 = r
    k3 = z1*r*bp/(b0 + x1*b1)
    k4 = z2*r*bp/(b0 + x2*b1)
    k1p = a + rp*b
    k2p = rp
    k3p = z3*rp*bp/(b0 + x1*b1)
    k4p = z4*rp*bp/(b0 + x2*b1)
    c1 = (A11*s + A12*sp)
    c2 = (A21*s + A22*sp)
    c3 = s1*bp + (A11*s + A12*sp)*b
    c4 = s1*(b0 + x1*b1)
    c5 = s2*bp + (A21*s + A22*sp)*b
    c6 = s2*(b0 + x2*b1)
    mpk1 = b
    mpk2 = b0
    mpk3 = b1
    mpk4 = bp
    
    # no known values

    unknown = [alpha, b, bp, b0, b1, r, rp, r0, r1, s, sp, s1, s2]

    k = [k1, k2, k4, k1p, k2p, k4p]
    c = [c1, c2, c3, c4, c5, c6]
    mpk = [mpk1, mpk2, mpk3, mpk4, 1]
    gp = []
    
    generate_abgw_input(a * s, k, c, mpk, unknown, [])

