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

"""
Decryption key attack against the PO17 scheme [1]

- Complete decryption attack
- Requires the corruption of one Attribute Authority [i]
- Requires the interaction with a second Attribute Authority [j]

[1] H. S. G. Pussewalage, and V. A. Oleshchuk, “A Distributed Multi-Authority Attribute Based Encryption Scheme for Secure Sharing of Personal Health Records”,
in SACMAT 17, pp. 255 - 262, ACM, 2017.
"""                             

import sys
from sympy import symbols
sys.path.insert(0, '../../core')                                                  

from decryption import DecryptionAttack
from decryption import DecryptionKeyCorruptionModel
from decryption import DecryptionKeyCorruptedVariable

def test_po17():

    alpha_i, alpha2, b, b2, r, s = symbols("alpha_i, alpha2, b, b2, r, s")

    k1 = (alpha_i - r) / b
    k2 = r
    c1 = s * b
    c2 = s * b2
    mpk1 = b

    k = [k1, k2]
    c = [c1, c2]
    mpk = [mpk1]
    gp = []

    mpk2 = b2


    decryption_attack = DecryptionAttack()
    decryption_attack.init(alpha_i * s, k, c, mpk, gp, [alpha_i, b, b2, r, s])

    # structure of AA[i]

    decryption_attack.add_mpk_AAi(mpk2)
    decryption_attack.add_mpk_AAj(mpk1)

    # set corruption model

    decryption_attack.set_corruption_model(DecryptionKeyCorruptionModel.AA_extended)
    
    # perform corruption, obtain b2
    
    decryption_attack.add_corruptable_var(DecryptionKeyCorruptedVariable.MPK_AAi, mpk2)

    decryption_attack.run()
    msg = decryption_attack.show_solution()        
                                                 
    assert msg.strip() == "[*] Decryption attack found: 1*k0[i]*c0 + 1/b2*k1[i]*c1", "[!] No solution found"
    print(msg)
    decryption_attack.format_encodings()

