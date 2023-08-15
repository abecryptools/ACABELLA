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
             
from common_methods import *
from sympy import *
from proof_generation import *
from proof_verification import * 
from ac17_correctness_checks import *

init_printing(use_unicode=True)


def verify_trivial_security(masterkey, special_s, kenc, cenc, benc, unknown, controlled, constraints):
    """
    The first two functions are for the AC17 case . It also verifies the trivial
    security of a scheme that satisfies the AC17 form.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.
        
    Returns:
        (bool): Trivial security verification.
    """    
    (eqsfound, eqs_to_analyze) = check_kernel_products(masterkey, special_s, kenc, cenc, benc, unknown)
    if not eqsfound:
        print("\n\t Failed!")
        return False
    else:
        at_least_one_nonzero = False
        for eq in eqs_to_analyze:
            if eq != 0:
                at_least_one_nonzero = True
        print("\n\t Passed! The security of the scheme depends on whether at least one of the following assumption(s) holds:")
        ctr = 1
        for eq in eqs_to_analyze:
            if type(eq) != int: 
                print("\n\t\t (" + str(ctr) + ") " + str(eq) + " != 0")
                ctr += 1
        if ctr == 1:
            print("\n\t\t None")
        return at_least_one_nonzero


def generate_the_proofs_and_check_collusion(masterkey, special_s, kenc, cenc, benc, unknown):
    """
    Verifies security against collusion of a scheme that satisfies the AC17 form.
    It uses the security proofs for this, which implies the collusion-security check
    in the generalized variant of this function.

    Parameters:
        masterkey (sp.core.list.Symbol): Sympy expression of the master key.
        special_s (sp.core.list.Symbol): Blinding factor.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.
        
    Returns:
        (bool): Collusion analysis result.
    """   
    (correct, kenc, cenc) = correct_form_silent(kenc, cenc, benc, unknown)
    collusion_secure = False
    if correct: 
        output = generate_proof_selective(masterkey, special_s, kenc, cenc, benc, unknown)
        output = normalize_substitutions(masterkey, special_s, output)
        if output[0] != None:
            result = verify_collusion_security_only(masterkey, special_s, kenc, cenc, benc, output)
            if not result:
                print("\n\t [!] The scheme is possibly insecure against collusion! \n")
        else:
            result = False
            print("\n\t [!] No selective proof found. The scheme is possibly insecure against collusion! \n")
            
        output2 = generate_proof_co_selective(masterkey, special_s, kenc, cenc, benc, unknown)
        output2 = normalize_substitutions(masterkey, special_s, output2)
        if output2[0] != None:
            result2 = verify_proof(masterkey, special_s, kenc, cenc, benc, output2)
            if result and result2:
                print("\n\t The scheme satisfies our collusion property and is thus secure against collusion. \n")
                collusion_secure = True
            else:
                print("\n\t [!] The scheme is possibly insecure against collusion! \n")
        else: 
            print("\n\t [!] No co-selective proof found. The scheme is possibly insecure against collusion! \n")
    return collusion_secure

## The functions below are for the generalized functionalities and work for all schemes, not just AC17 ones. ##


def verify_trivial_security_generalized(blindingvalue, kenc, cenc, benc, unknown):
    """
    Verifies the trivial security of the scheme. The blinding value is what masks the message.

    Parameters:

        blindingvalue (sp.core.list.Symbol): What masks the message.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.
        
    Returns:
        (bool): Verification result.
    """   
    penc = gen_all_p(kenc, cenc, benc, [])
    penc = canonical(penc)
    
    denoms = collect_denoms(penc, unknown)
    denomprod = denoms_prod(denoms)
    penc = transform_encoding_list(denomprod, penc)
    blindingvalue = canonical([cancel(blindingvalue * denomprod)])[0]
    
    (mat, uvector) = writeencodingasprod(penc, unknown)
    mat = Matrix(mat)
    
    luvec1 = len(uvector)
    target_vector = Matrix([writepolyasprod(blindingvalue, uvector, unknown)])
    luvec2 = len(uvector)
    if luvec1 != luvec2:
        print("\n\t Passed! The blinding value contains terms that cannot be created with the rest of the ciphertext and the key. However, because of this property, collusion security cannot be verified.")
        return (False, None, None, None, None)

    list_bv_indices = []
    ctr = 0
    for elem in target_vector:
        if elem != 0:
            list_bv_indices.append(ctr)
        ctr += 1

    kern = mat.nullspace()
    
    kern_red = []
    kern_remainder = []
    for vec in kern:
        at_least_one_zero = False
        for ind in list_bv_indices:
            if vec[ind] != 0:
                at_least_one_zero = True
        if at_least_one_zero:
            kern_red.append(vec)
        else:
            kern_remainder.append(vec)
    
    if len(kern_red) == 0:
        print("\n\t Failed!")
        return (False, None, None, None, None)
    
    print("\n\t If there exists a solution for the following system of equations:")
    msg = ""
    ctr = 1
    ctr2 = 0
    for ind in range(len(list_bv_indices)):
        msg2 = "\n\t\t (" + str(ctr) + ") "
        first = True
        at_least_one_nonzero = False
        for ind2 in range(len(kern_red)):
            eq_is_zero = False
            el = cancel(kern_red[ind2][list_bv_indices[ind]])
            if not el.is_integer:
                eq = "(" + str(el) + ")"
                at_least_one_nonzero = True
            else:
                if el != 0:
                    eq = str(el)
                    at_least_one_nonzero = True
                else:
                    eq_is_zero = True
            
            if not eq_is_zero:
                if not first: 
                    msg2 += " + c" + str(ind2) + "*" + eq
                else: 
                    msg2 += " c" + str(ind2) + "*" + eq
                    first = False
        if at_least_one_nonzero:
            msg2 += " = " + "d" + str(ctr2) #str(target_vector[list_bv_indices[ind]])
            msg += msg2
        else: 
            msg += msg2 + " 0 = " + "d" + str(ctr2) #+ str(target_vector[list_bv_indices[ind]])
        ctr += 1
        ctr2 += 1
    
    msg2 = "\n\t\t (" + str(ctr) + ") "
    ctr3 = 0
    first = True
    for ind in range(len(list_bv_indices)):
        if not first:
            msg2 += " +"
        else:
            first = False
        el = target_vector[list_bv_indices[ind]]
        if not el.is_integer:
            msg2 += " d" + str(ctr3) + "*(" + str(el) + ")"
        else:
            msg2 += " d" + str(ctr3) + "*" + str(el)
        ctr3 += 1
    msg2 += " != 0"
    msg += msg2
    
    print(msg)
    if len(kern_red) > 1:
        if len(kern_red) > 2:
            cstring = "c0,...,c" + str(len(kern_red) - 1) + ","
        else:
            cstring = "c0,c1,"
    else:
        cstring = "c0,"
    
    if len(list_bv_indices) > 1:
        if len(list_bv_indices) > 2:
            dstring = "d0,...,d" + str(len(list_bv_indices) - 1)
        else:
            dstring = "d0,d1"
    else:
        dstring = "d0"
    
    print("\n\t where " + cstring + dstring + " denote the coefficients, then the scheme is trivially secure.")
    
    kern_red2 = []
    for vec in kern_red:
        if sum(target_vector[i] * vec[i] for i in range(len(target_vector))) != 0:
            kern_red2.append(vec)
    
    if len(kern_red2) > 0:
        return (True, kern_red + kern_remainder, uvector, target_vector, list_bv_indices)
    else:
        return (False, kern_red + kern_remainder, uvector, target_vector, list_bv_indices)

def obtain_masterkeys(blindingvalue, kenc, cenc, benc, unknown):
    """
    Obtains the master keys from the encodings.

    Parameters:

        blindingvalue (sp.core.list.Symbol): What masks the message.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.
        
    Returns:
        (list): Master keys.
        (list): Key encodings.
        (list): Ciphertext encodings.
        (list): Public key encodings.
    """ 
    lis_vars_blindingvalue = get_vars_polynomial(blindingvalue)
    lis_vars_kenc = get_vars_list_polynomials(kenc)
    lis_vars_cenc = get_vars_list_polynomials(cenc)
    lis_vars_benc = get_vars_list_polynomials(benc)
    
    lis_masterkeys = []
    for elem in lis_vars_blindingvalue:
        is_unknown = (elem in unknown)
        in_key = (elem in lis_vars_kenc)
        not_in_cenc = not (elem in lis_vars_cenc)
        not_in_benc = not (elem in lis_vars_benc)
        if is_unknown and in_key and not_in_cenc and not_in_benc:
            lis_masterkeys.append(elem)
    return (lis_masterkeys, lis_vars_kenc, lis_vars_cenc, lis_vars_benc)

def reduce_kern(indices, kern):
    """
    Removes all the kernel vectors that are all-zero in the given indices.

    Parameters:

        indices (list): Indices.
        kern (list): Kernel.
        
    Returns:
        (list): New kernel.
    """ 
    new_kern = []
    for vec in kern:
        at_least_one_nonzero = False
        for ind in indices:
            if vec[ind] != 0:
                at_least_one_nonzero = True
        if at_least_one_nonzero:
            new_kern.append(vec)
    return new_kern

def remove_kern_unnecessary_vecs(bv_indices, shared_indices_not_bv, kern):
    """
    Removes all kernel vectors that do not contribute to solution.

    Parameters:

        bv_indices (list): Indices.
        shared_indices_not_bv (list): Shared indices.
        kern (list): Kernel.
        
    Returns:
        (list): New kernel.
    """ 
    new_kern = []
    kern_remainder = []
    for vec in kern:
        allzero = True
        for ind in bv_indices:
            if vec[ind] != 0:
                allzero = False
        if allzero:
            kern_remainder.append(vec)
    
    kern_vecs_removed = []
    for ind in shared_indices_not_bv:
        non_zeros = []
        ctr = 0
        for vec in kern:
            if vec in kern_remainder and vec[ind] != 0:
                non_zeros.append(ctr)
            ctr += 1
        if len(non_zeros) == 1:
            if not non_zeros[0] in kern_vecs_removed:
                kern_vecs_removed.append(non_zeros[0])
    
    ctr = 0
    for vec in kern:
        if not ctr in kern_vecs_removed:
            new_kern.append(vec)
        ctr += 1
    return new_kern

def verify_collusion_security_generalized(blindingvalue, kenc, cenc, benc, unknown, kern, uvector, target_vector, list_bv_indices):
    """
    Checks whether the scheme is secure against collusion.
   
    Parameters:
        blindingvalue (sp.core.list.Symbol): Blinding value.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.
        kern (list): Kernel.
        uvector (list): Unknown variables vector.
        target_vector (list): Target.
        list_bv_indices (list): Indices.
    """    
    (lis_masterkeys, lis_vars_kenc, lis_vars_cenc, lis_vars_benc) = obtain_masterkeys(blindingvalue, kenc, cenc, benc, unknown)
    
    lis_shared_indices = []
    for ind in range(len(uvector)):
        vars_elem = get_vars_polynomial(uvector[ind])
        is_shared = True
        for var in vars_elem:
            if (var in lis_vars_kenc) and not (var in lis_vars_benc) and not (var in lis_masterkeys):
                is_shared = False
        if is_shared:
            lis_shared_indices.append(ind)
    
    lis_shared_indices_not_bv = [ind for ind in lis_shared_indices if not ind in list_bv_indices]

    kern = reduce_kern(lis_shared_indices, kern)
    
    kern = remove_kern_unnecessary_vecs(list_bv_indices, lis_shared_indices_not_bv, kern)

    transcript_found = print_transcript_to_trivial_and_collusion_security(kern, uvector, target_vector, list_bv_indices, lis_shared_indices_not_bv)
    
    if not transcript_found:
        print("\n\t If there exists a solution for the previous system of equations such that the following system of equations holds:")
        msg = ""
        ctr = 1
        for ind in lis_shared_indices_not_bv:
            msg2 = "\n\t\t (" + str(ctr + len(list_bv_indices) + 1) + ") "
            first = True
            at_least_one_nonzero = False
            for ind2 in range(len(kern)):
                eq_is_zero = False
                el = cancel(kern[ind2][ind])
                if not el.is_integer:
                    eq = "(" + str(el) + ")"
                    at_least_one_nonzero = True
                else:
                    if el != 0:
                        eq = str(kern[ind2][ind])
                        at_least_one_nonzero = True
                    else:
                        eq_is_zero = True
                
                if not eq_is_zero:
                    if not first: 
                        msg2 += " + c" + str(ind2) + "*" + eq
                    else: 
                        msg2 += " c" + str(ind2) + "*" + eq
                        first = False
            if at_least_one_nonzero:
                msg2 += " = 0,"
                msg += msg2
                ctr += 1
        print(msg)
        print("\n\t then the scheme is secure against collusion. If not, then the scheme may be vulnerable to a collusion attack.")

def print_transcript_to_trivial_and_collusion_security(kern, uvector, target_vector, list_bv_indices, lis_shared_indices_not_bv):
    """
    Generates and prints a transcript that proves trivial and collusion security of the scheme.

    Parameters:
        kern (list): Kernel.
        uvector (list): Unknown variables vector.
        target_vector (list): Target.
        list_bv_indices (list): Indices.
        lis_shared_indices_not_bv: Shared indices that are not in bv.
    """    
    print("\n\t Attempting to compute transcript to trivial and collusion security..")
    
    kern_short = []
    for vec in kern:
        vec_s = []
        for ind in lis_shared_indices_not_bv:
            vec_s.append(vec[ind])
        kern_short.append(vec_s)
    
    mat_kern_short = Matrix([Matrix(vec).transpose() for vec in kern_short])
    mks_ns = mat_kern_short.transpose().nullspace()
    
    if len(mks_ns) == 0:
        print("\n\t The system could not find a transcript.")
        return False
    
    kern_red = []
    for ks_vec in mks_ns:
        vec = cancel(ks_vec[0]*kern[0])
        for ind in range(1,len(ks_vec)):
            vec += cancel(ks_vec[ind]*kern[ind])
        kern_red.append(vec)

    kern_red2 = []
    for vec in kern_red:
        if sum(target_vector[i] * vec[i] for i in range(len(target_vector))) != 0:
            kern_red2.append(vec)
    
    if len(kern_red2) == 0:
        print("\n\t The system could not find a transcript.")
        return False
    
    kern_vec = cancel(kern_red2[0])
    for vec in kern_red2[1:]:
        kern_vec += vec
    
    print("\n\t The system found a transcript, so the scheme is trivially secure and secure against collusion.")
    
    print("\t Substitutions for the terms associated with the blinding value:")
    for ind in list_bv_indices:
        print("\n\t\t - " + str(uvector[ind]) + " : " + str(kern_vec[ind]))
    
    print("\n\t Substitutions for the special terms that are shared among keys and are not associated with the blinding value:")
    for ind in lis_shared_indices_not_bv:
        print("\n\t\t - " + str(uvector[ind]) + " : " + str(kern_vec[ind]))
    
    lis_rest_indices = [ind for ind in range(len(uvector)) if not ind in list_bv_indices and not ind in lis_shared_indices_not_bv]
    print("\n\t Substitutions for the rest of the terms:")
    for ind in lis_rest_indices:
        print("\n\t\t - " + str(uvector[ind]) + " : " + str(kern_vec[ind]))
    return True

def analysis_trivial_and_collusion_security(blindingvalue, kenc, cenc, benc, unknown):
    """
    Analyzes the trivial and collusion security of the scheme.

    Parameters:
        blindingvalue (sp.core.list.Symbol): Blinding value.
        kenc (list): Key encodings.
        cenc (list): Ciphertext encodings.
        benc (list): Public key encodings.
        unknown (list): Unknown variables.
    
    Returns:
        (bool): The scheme is trivial secure.
        (bool): The scheme is collusion secure.
    """    
    pprint("\t\tMPK encodings: \t\t\t" + str(benc) + "\n", use_unicode=True)
    pprint("\t\tKey encodings: \t\t\t" + str(kenc) + "\n", use_unicode=True)
    pprint("\t\tCiphertext encodings: \t" + str(cenc) + "\n", use_unicode=True)

    trivial_secure = False
    collusion_secure = False

    print("\n == Performing simple trivial security check.. ==")
    (trivial_secure, kern, uvector, target_vector, list_bv_indices) = verify_trivial_security_generalized(blindingvalue, kenc, cenc, benc, unknown)
    if trivial_secure:
        print("\n\t The scheme is probably trivially secure, because there exists a solution for the equations.")
    else:
        print("\n\t The scheme may not be trivially secure, because no solution could be found.")

    print("\n == Performing collusion security check.. ==")
    collusion_secure = verify_collusion_security_generalized(blindingvalue, kenc, cenc, benc, unknown, kern, uvector, target_vector, list_bv_indices)

    return trivial_secure, collusion_secure

if __name__ == "__main__":

    # BSW07

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
    
    # verify_trivial_security_generalized(alpha*s, k, c, mpk, unknown)

    analysis_trivial_and_collusion_security(alpha * s, k, c, mpk, unknown)