# -*- coding: utf-8 -*-

from common_methods import *
from sympy import *
from proof_generation import *
from proof_verification import * 
from ac17_correctness_checks import *

init_printing(use_unicode=True)

## The first two functions are for the AC17 case ##
# verifies the trivial security of a scheme that satisfies the AC17 form
def verify_trivial_security(masterkey, special_s, kenc, cenc, benc, unknown, controlled, constraints):
    (eqsfound, eqs_to_analyze) = check_kernel_products(masterkey, special_s, kenc, cenc, benc, unknown)
    if not eqsfound:
        print("\n\t Failed!")
        return False
    else:
        at_least_one_nonzero = False
        for eq in eqs_to_analyze:
            # sols = solve(eq, controlled, dict=True)
            # if len(sols) == 0:
            #     at_least_one_nonzero = True
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

# verifies security against collusion of a scheme that satisfies the AC17 form
# uses the security proofs for this, which implies the collusion-security check
# in the generalized variant of this function
def generate_the_proofs_and_check_collusion(masterkey, special_s, kenc, cenc, benc, unknown):
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

# verifies the trivial security of the scheme
# the blinding value is what masks the message
def verify_trivial_security_generalized(blindingvalue, kenc, cenc, benc, unknown):
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

    """
    penc_new = trim_penc_vector(penc, mat1, target_vector1, unknown)
    denoms2 = collect_denoms(penc_new, unknown)
    denomprod2 = denoms_prod(denoms2)
    penc_new = transform_encoding_list(denomprod2, penc_new)
    (mat, uvector) = writeencodingasprod(penc_new, unknown)
    mat = Matrix(mat)
    blindingvalue_new = canonical([cancel(blindingvalue * denomprod2)])[0]
    
    luvec1 = len(uvector)
    target_vector = Matrix([writepolyasprod(blindingvalue_new, uvector, unknown)])
    luvec2 = len(uvector)
    if luvec1 != luvec2:
        print("\n\t Passed! The blinding value contains terms that cannot be created with the rest of the ciphertext and the key. However, because of this property, collusion security cannot be verified.")
        return (False, None, None, None, None)
    """ 

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
    
    solution = True
    
    print("\n\t If there exists a solution for the following system of equations:")
    msg = ""
    ctr = 1
    for ind in range(len(list_bv_indices)):
        msg2 = "\n\t\t (" + str(ctr) + ") "
        first = True
        at_least_one_nonzero = False
        for ind2 in range(len(kern_red)):
            eq_is_zero = False
            el = cancel(kern_red[ind2][ind])
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
            msg2 += " = " + str(target_vector[list_bv_indices[ind]])
            msg += msg2
        else: 
            msg += msg2 + " 0 = " + str(target_vector[list_bv_indices[ind]])
            solution = False
        ctr += 1
    print(msg)
    if len(kern_red) > 1:
        print("\n\t where c0,...,c" + str(len(kern_red)-1) + " denote the coefficients, then the scheme is trivially secure.")
    else:
        print("\n\t where c0 denotes a coefficient, then the scheme is trivially secure.")
    
    return (solution, kern_red + kern_remainder, uvector, target_vector, list_bv_indices)

# trims the penc vector based on combinations that cannot be canceled by others
def trim_penc_vector(penc, mat, target_vector, unknown):
    mat_rows = mat.shape[0]
    lis_remove = []
    for ind in range(len(unknown)):
        lis_rows = []
        nr_lis_rows = 0
        if target_vector[ind] != 0:
            lis_rows.append(mat_rows)
            nr_lis_rows += 1
        for i in range(mat_rows):
            if mat[i,ind] != 0:
                lis_rows.append(i)
                nr_lis_rows += 1
        if nr_lis_rows == 1:
            row_nr = lis_rows[0]
            if (row_nr != mat_rows) and (not row_nr in lis_remove):
                lis_remove.append(row_nr)
    new_penc = []
    for ind in range(len(penc)):
        if not ind in lis_remove:
            new_penc.append(penc[ind])
    return new_penc

# obtains the master keys from the encodings
def obtain_masterkeys(blindingvalue, kenc, cenc, benc, unknown):
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

# removes all the kernel vectors that are all-zero in the given indices
def reduce_kern(indices, kern):
    new_kern = []
    for vec in kern:
        at_least_one_nonzero = False
        for ind in indices:
            if vec[ind] != 0:
                at_least_one_nonzero = True
        if at_least_one_nonzero:
            new_kern.append(vec)
    return new_kern

# checks whether the scheme is secure against collusion
def verify_collusion_security_generalized(blindingvalue, kenc, cenc, benc, unknown, kern, uvector, target_vector, list_bv_indices):
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

    transcript_found = print_transcript_to_trivial_and_collusion_security(kern, uvector, target_vector, list_bv_indices, lis_shared_indices_not_bv)
    
    if not transcript_found:
        print("\n\t If there exists a solution for the previous system of equations such that the following system of equations holds:")
        msg = ""
        ctr = 1
        for ind in lis_shared_indices_not_bv:
            msg2 = "\n\t\t (" + str(ctr + len(list_bv_indices)) + ") "
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

# generates and prints a transcript that proves trivial and collusion security of the scheme
def print_transcript_to_trivial_and_collusion_security(kern, uvector, target_vector, list_bv_indices, lis_shared_indices_not_bv):
    print("\n\t Attempting to compute transcript to trivial and collusion security..")
    kern_short = []
    for vec in kern:
        vec_s = []
        for ind in list_bv_indices:
            vec_s.append(vec[ind])
        for ind in lis_shared_indices_not_bv:
            vec_s.append(vec[ind])
        kern_short.append(vec_s)
    
    ones_and_zeros_row = [target_vector[ind] for ind in list_bv_indices] + [0 for ind in lis_shared_indices_not_bv]
    kern_short.append(ones_and_zeros_row)
    mat_kern_short = Matrix([Matrix(vec).transpose() for vec in kern_short])
    mks_ns = mat_kern_short.transpose().nullspace()
    sol_found = False
    for vec in mks_ns:
        if vec[-1] != 0:
            sol_found = True
            val = vec[-1]
            sol_vec = vec

    if not sol_found:
        print("\n\t The system could not find a transcript.")
        return False
    else:
        if val != -1:
            ctr = 0
            for ind in sol_vec:
                sol_vec[ctr] = cancel(-sol_vec[ctr]/val)
                ctr += 1
    
        kern_vec = cancel(kern[0].transpose()*sol_vec[0])
        for ind in range(len(sol_vec)-2):
            kern_vec += cancel(kern[ind + 1].transpose()*sol_vec[ind + 1])
            
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

# analyzes the trivial and collusion security of the scheme
def analysis_trivial_and_collusion_security(blindingvalue, kenc, cenc, benc, unknown):
    pprint("\t\tMPK encodings: \t\t\t" + str(benc) + "\n", use_unicode=True)
    pprint("\t\tKey encodings: \t\t\t" + str(kenc) + "\n", use_unicode=True)
    pprint("\t\tCiphertext encodings: \t" + str(cenc) + "\n", use_unicode=True)

    trivial_secure = False
    collusion_secure = False

    print("\n == Performing simple trivial security check.. ==")
    (trivial_secure, kern, uvector, target_vector, list_bv_indices) = verify_trivial_security_generalized(blindingvalue, kenc, cenc, benc, unknown)

    if trivial_secure:
        print("\n == Performing collusion security check.. ==")
        collusion_secure = verify_collusion_security_generalized(blindingvalue, kenc, cenc, benc, unknown, kern, uvector, target_vector, list_bv_indices)
    else:
        print("\n The scheme is probably not trivially secure, because there exists no solution for the equations.")

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
    
    verify_trivial_security_generalized(alpha*s, k, c, mpk, unknown)

    # analysis_trivial_and_collusion_security(alpha * s, k, c, mpk, unknown)