# -*- coding: utf-8 -*-

from common_methods import *
from sympy import *

init_printing(use_unicode=True)

def generate_proof_co_selective(masterkey, special_s, kenc, cenc, benc, unknown):
    output = generate_proof_selective(masterkey, special_s, cenc, kenc, benc, unknown)
    (benc_mats, rvectors_nonlone, rvectors_lone, svectors_nonlone, svectors_lone) = output
    
    if benc_mats == None:
        return output
    
    benc_mats_new = []
    for (bx, mat) in benc_mats:
        mat_new = mat.transpose()
        benc_mats_new.append((bx, mat_new))
    
    rvectors_nonlone_new = []
    for (k, vec) in rvectors_nonlone:
        vec_new = vec.transpose()
        rvectors_nonlone_new.append((k, vec_new))
        
    rvectors_lone_new = []
    for (k, vec) in rvectors_lone:
        vec_new = vec.transpose()
        rvectors_lone_new.append((k, vec_new))
    
    svectors_nonlone_new = []
    for (c, vec) in svectors_nonlone:
        vec_new = vec.transpose()
        svectors_nonlone_new.append((c, vec_new))
    
    svectors_lone_new = []
    for (c, vec) in svectors_lone:
        vec_new = vec.transpose()
        svectors_lone_new.append((c, vec_new))
    
    output = (benc_mats_new, svectors_nonlone_new, svectors_lone_new, rvectors_nonlone_new, rvectors_lone_new)
    return output

def generate_proof_selective(masterkey, special_s, kenc, cenc, benc, unknown):
    kenc = canonical(kenc)
    cenc = canonical(cenc)
    (matk, uvectork) = writeencodingasprod(kenc, unknown)
    (matc, uvectorc) = writeencodingasprod(cenc, unknown)
    
    Mat_k = Matrix(matk)
    Mat_c = Matrix(matc)
    
    nonlone_c = determine_non_lone_vars_in_uvector(cenc, benc, uvectorc)
    
    (sublist_nonlones_c, sublist_lones_c) = sublistslonenonlone(nonlone_c)
    
    sublist_nonlones_c = put_special_s_first_entry(special_s, sublist_nonlones_c)
    
    (Mat_c, uvectorc) = extend_mat_and_vec(Mat_c, uvectorc, benc, sublist_nonlones_c)
    
    kern_c = Mat_c.nullspace()
    
    if len(kern_c) == 0:
        # print("\n - No proof found.\n")
        return (None, None, None, None, None)
    (benc_mats, _) = construct_benc_mats(benc, sublist_nonlones_c, uvectorc, kern_c)
    
    nonlone_k = determine_non_lone_vars_in_uvector(kenc, benc, uvectork)
    
    (sublist_nonlones_k, sublist_lones_k) = sublistslonenonlone(nonlone_k)
    
    bm_sh = shape(benc_mats[0][1])
    bm_rows = bm_sh[0]
    bm_columns = bm_sh[1]
    
    svectors_nonlone = []
    count = 0
    for c in sublist_nonlones_c:
        vec = zeros(1,bm_rows)
        vec[count] = 1
        svectors_nonlone.append((c, vec))
        count += 1
        
    svectors_lone = construct_lone_vects(benc, sublist_lones_c, uvectorc, kern_c, bm_columns)
    
    (big_matrix, big_uvector) = merge_matrices(Mat_c, Mat_k, uvectorc, uvectork, sublist_nonlones_c, sublist_nonlones_k)
    kern_bm = big_matrix.nullspace()
    if len(kern_bm) == 0:
        return (None, None, None, None, None)
    
    kern_vec = select_kern_vec(masterkey, special_s, sublist_nonlones_c, kern_bm, big_uvector)
    
    rvectors_nonlone = get_nonlone_vecs(kern_vec, kern_c, uvectorc, big_uvector, sublist_nonlones_k)
    rvectors_lone = get_lone_vecs(kern_vec, big_uvector, sublist_lones_k, sublist_nonlones_c)
    
    output = (benc_mats, svectors_nonlone, svectors_lone, rvectors_nonlone, rvectors_lone)
    return output

def generate_proof_selective_deprecated(masterkey, special_s, kenc, cenc, benc, unknown):
    kenc = canonical(kenc)
    cenc = canonical(cenc)
    (matk, uvectork) = writeencodingasprod(kenc, unknown)
    (matc, uvectorc) = writeencodingasprod(cenc, unknown)
    
    Mat_k = Matrix(matk)
    Mat_c = Matrix(matc)
    
    nonlone_c = determine_non_lone_vars_in_uvector(cenc, benc, uvectorc)
    
    (sublist_nonlones_c, sublist_lones_c) = sublistslonenonlone(nonlone_c)
    
    sublist_nonlones_c = put_special_s_first_entry(special_s, sublist_nonlones_c)
    
    (Mat_c, uvectorc) = extend_mat_and_vec(Mat_c, uvectorc, benc, sublist_nonlones_c)
    
    kern_c = Mat_c.nullspace()
    
    print("kern\n")
    pprint(kern_c)
    
    if len(kern_c) == 0:
        # print("\n - No proof found.\n")
        return (None, None, None, None, None)
    (benc_mats, notinitb) = construct_benc_mats(benc, sublist_nonlones_c, uvectorc, kern_c)
    
    print(benc_mats)
    
    nonlone_k = determine_non_lone_vars_in_uvector(kenc, benc, uvectork)
    
    (sublist_nonlones_k, sublist_lones_k) = sublistslonenonlone(nonlone_k)
    
    kern_k = Mat_k.nullspace()
    
    """
    # keeping this code until sure it can be removed
    if len(notinitb) > 0 and len(kern_k) > 0:
        kern_vec = kern_k[0]
        for ind in range(1,len(kern_k)):
            kern_vec += kern_k[ind]
        (benc_mats_remainder,_) = construct_benc_mats(notinitb, sublist_nonlones_k, uvectork, [kern_vec])
        if len(benc_mats_remainder) > 0:
            benc_mats = unify_benc_mats(benc_mats, benc_mats_remainder)
    """
   
    bm_sh = shape(benc_mats[0][1])
    bm_rows = bm_sh[0]
    bm_columns = bm_sh[1]
    
    svectors_nonlone = []
    count = 0
    for c in sublist_nonlones_c:
        vec = zeros(1,bm_rows)
        vec[count] = 1
        svectors_nonlone.append((c, vec))
        count += 1
        
    svectors_lone = construct_lone_vects(benc, sublist_lones_c, uvectorc, kern_c, bm_columns)
    
    if len(kern_k) == 0:
        # print("\n - No proof found.\n")
        return (None, None, None, None, None)
    
    """
    # keeping the old code here for a bit before deleting it forever
    (sol_list, large_solution_matrix) = make_solution_matrix(benc_mats, kern_k, uvectork, sublist_nonlones_k)
        
    kern_lm = large_solution_matrix.nullspace()
    
    if len(kern_lm) == 0:
        # print("\n - No proof found.\n")
        return (None, None, None, None, None)
    
    (rvectors_nonlone, kern_vec) = get_nonlone_vectors(kern_lm, bm_columns, sublist_nonlones_k)
    """
    
    # """
    # keeping this code too
    kern_lm_is_empty = True
    rvectors_init = False
    
    for kern_k_el in kern_k:
        (sol_list, large_solution_matrix) = make_solution_matrix(benc_mats, kern_k, uvectork, sublist_nonlones_k)
            
        kern_lm = large_solution_matrix.nullspace()
        
        if len(kern_lm) > 0:
            kern_lm_is_empty = False
            (rvectors_nonlone_new, kern_vec_new) = get_nonlone_vectors(kern_lm, bm_columns, sublist_nonlones_k)
            if rvectors_init:
                (rvectors_nonlone, kern_vec) = add_rvectors_nonlone_kern_vec(rvectors_nonlone, kern_vec, rvectors_nonlone_new, kern_vec_new)
            else:
                (rvectors_nonlone, kern_vec) = (rvectors_nonlone_new, kern_vec_new)
                rvectors_init = True
    
    if kern_lm_is_empty:
        # print("\n - No proof found.\n")
        return (None, None, None, None, None)
    # """
    
    (big_matrix, big_uvector) = merge_matrices(Mat_c, Mat_k, uvectorc, uvectork, sublist_nonlones_c, sublist_nonlones_k)
    kern_bm = big_matrix.nullspace()
    if len(kern_bm) == 0:
        return (None, None, None, None, None)
    
    kern_vec = select_kern_vec(masterkey, special_s, sublist_nonlones_c, kern_bm, big_uvector)
    
    """
    kern_vec = kern_bm[0]
    for kern_vec2 in kern_bm[1:]:
        kern_vec += kern_vec2
        
    print(kern_vec)
    """
    
    rvectors_nonlone2 = get_nonlone_vecs(kern_vec, kern_c, uvectorc, big_uvector, sublist_nonlones_k)
    rvectors_lone2 = get_lone_vecs(kern_vec, big_uvector, sublist_lones_k, sublist_nonlones_c)
    print(svectors_nonlone, benc_mats, rvectors_lone2)
    # new ends here
    
    rvectors_lone = get_lone_vectors(kern_vec, kern_k, sublist_lones_k, uvectork, len(sublist_nonlones_k), bm_rows, bm_columns)
    
    output = (benc_mats, svectors_nonlone, svectors_lone, rvectors_nonlone2, rvectors_lone2)
    return output

# ensures that the first entry of the master-key and special non-lone s is 1
def normalize_substitutions(masterkey, special_s, proofs):
    (benc_mats, svectors_nonlone, svectors_lone, rvectors_nonlone, rvectors_lone) = proofs
    
    nm_factor_keys = 1
    nm_factor_ct = 1
    swap = False
    init_key = False
    if rvectors_lone != None:
        for (k, vec) in rvectors_lone:
            if k == masterkey:
                master_key_vec = vec
                init_key = True
    
    init_ct = False
    if svectors_nonlone != None:
        for (c, vec) in svectors_nonlone:
            if c == special_s:
                special_s_vec = vec
                init_ct = True
    
    ind = 0
    if init_key and init_ct:
        if master_key_vec[0] == 0 or special_s_vec[0] == 0:
            for i in range(len(master_key_vec)):
                if master_key_vec[i] != 0 and special_s_vec[i] != 0:
                    ind = i
                    swap = True
                    nm_factor_keys = master_key_vec[i]
                    nm_factor_ct = special_s_vec[i]
        else:
            nm_factor_keys = master_key_vec[0]
            nm_factor_ct = special_s_vec[0]
    
        if rvectors_lone != None:
            ctr_vecs = 0
            for (k, vec) in rvectors_lone:
                if swap:
                    vec = vec.elementary_row_op('n<->m',0,ind)
                    rvectors_lone[ctr_vecs] = (k, vec)
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry/nm_factor_keys)
                    ctr += 1
                ctr_vecs+= 1
        
        if rvectors_nonlone != None:
            for (k, vec) in rvectors_nonlone:
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry/nm_factor_keys)
                    ctr += 1
        
        if svectors_nonlone != None:
            ctr_vecs = 0
            for (c, vec) in svectors_nonlone:
                if swap:
                    vec = vec.elementary_col_op('n<->m',0,ind)
                    svectors_nonlone[ctr_vecs] = (c, vec)
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry/nm_factor_ct)
                    ctr += 1
                ctr_vecs += 1
        
        if svectors_lone != None:
            for (c, vec) in svectors_lone:
                ctr = 0
                for entry in vec:
                    vec[ctr] = simplify(entry/nm_factor_ct)
                    ctr += 1
        
        if swap:
            ctr_rows =  0
            for (b, mat) in benc_mats:
                mat = mat.elementary_row_op('n<->m',0,ind)
                benc_mats = (b, mat)
                ctr_rows += 1
    
    return proofs

# merges the matrix for the ciphertext and key encodings
def merge_matrices(matc, matk, uvectorc, uvectork, nonlones_c, nonlones_k):
    len_nl_c = len(nonlones_c)
    len_nl_k = len(nonlones_k)
    matc_rows = shape(matc)[0]
    matc_cols = shape(matc)[1]
    matk_rows = shape(matk)[0]
    matk_cols = shape(matk)[1]
    
    big_uvectorc = []
    for x_k in nonlones_k:
        big_uvectorc += [x_k * i for i in uvectorc]
    
    big_uvectork = []
    for x_c in nonlones_c:
        big_uvectork += [x_c * i for i in uvectork]
       
    big_uvector = []
    big_uvector += big_uvectorc
    for x_u in big_uvectork:
        if not x_u in big_uvector:
            big_uvector.append(x_u)
             
    big_matc = zeros(matc_rows*len_nl_k, matc_cols*len_nl_k)
    big_matk = zeros(matk_rows*len_nl_c, matk_cols*len_nl_c)
    ctr = 0
    for x_k in nonlones_k:
        for i in range(matc_rows):
            for j in range(matc_cols):
                big_matc[i + ctr*matc_rows, j + ctr*matc_cols] += matc[i,j]
        ctr += 1
    
    ctr = 0
    for x_c in nonlones_c:
        for i in range(matk_rows):
            for j in range(matk_cols):
                big_matk[i + ctr*matk_rows, j + ctr*matk_cols] += matk[i,j]
        ctr += 1
     
    big_matc_rows = matc_rows*len_nl_k
    big_matk_rows = matk_rows*len_nl_c
    big_mat = zeros(big_matc_rows + big_matk_rows, len(big_uvector))
    i_u = 0
    for x_u in big_uvector:
        i = 0
        for x_c in big_uvectorc:
            if x_u == x_c:
                for j in range(big_matc_rows):
                    big_mat[j,i_u] += big_matc[j,i]
            i += 1
        
        i = 0
        for x_k in big_uvectork:
            if x_u == x_k:
                for j in range(big_matk_rows):
                    big_mat[j + big_matc_rows,i_u] += big_matk[j,i]
            i += 1
        
        i_u += 1
    
    return (big_mat, big_uvector)

# generates the vectors for the non-lone variables based on the large kernel
def get_nonlone_vecs(kern_vec, kern_c, uvectorc, big_uvector, nonlones_k):
    rvectors_nonlone = []
    ctr = 0
    for nl_el in nonlones_k:
        sub_vec = []
        for i in range(ctr, ctr + len(uvectorc)):
            sub_vec.append(kern_vec[i,0])
        sub_vec = Matrix(sub_vec)
        
        new_mat = Matrix([vec.transpose() for vec in kern_c + [sub_vec]]).transpose()
        
        ns_new_mat = new_mat.nullspace()
        for ns_vec in ns_new_mat:
            if ns_vec[-1] != 0:
                ns_vec2 = [-i/ns_vec[-1] for i in ns_vec[:-1]]
                rvectors_nonlone.append((nl_el, Matrix(ns_vec2)))
        ctr += len(uvectorc)
    
    return rvectors_nonlone

# generates the vectors for the lone variables based on the large kernel
def get_lone_vecs(kern_vec, big_uvector, lones_k, nonlones_c):
    rvectors_lone = []
    for l_el in lones_k:
        rvec = []
        for nl_el in nonlones_c:
            prd = l_el * nl_el
            if prd in big_uvector:
                ind = big_uvector.index(prd)
                rvec.append(kern_vec[ind])
            else:
                rvec.append(0)
        rvectors_lone.append((l_el, Matrix(rvec)))
    return rvectors_lone

# selects the kern vector that has 1 in the entry corresponding to alpha * s
# and 0 in all other combinations of alpha and nonlones
def select_kern_vec(masterkey, special_s, nonlones, kern_bm, big_uvector):
    sub_kern = []
    mk_entry = big_uvector.index(masterkey * special_s)
    null_entries = []
    for el in [i for i in nonlones if i != special_s]:
        if masterkey * el in big_uvector:
            null_entries.append(big_uvector.index(masterkey * el))
    
    for vec in kern_bm:
        vec_qualified = (vec[mk_entry] != 0)
        for en in null_entries:
            vec_qualified = vec_qualified and (vec[en] == 0)
        if vec_qualified:
            sub_kern.append(vec)
    
    if len(sub_kern) > 0:
        kern_vec = sub_kern[0]
        for vec in sub_kern[1:]:
            kern_vec += vec
    else: 
        kern_vec = kern_bm[0]
    
    return kern_vec

# ensures that the special_s is in the first entry of the sublist
def put_special_s_first_entry(special_s, sublist):
    ctr = 0
    entry = 0
    for x_s in sublist:
        if x_s == special_s:
            entry = ctr
        ctr += 1
    cpy_first = sublist[0]
    sublist[0] = special_s
    sublist[entry] = cpy_first
    return sublist

# extends the matrix and uvector with combinations that are not in the encodings
def extend_mat_and_vec(matc, uvectorc, benc, nonlones):
    zero_vec = zeros(shape(matc)[0],1)
    nr_cols = shape(matc)[1]
    for x_b in benc:
        for x_c in nonlones:
            prod = x_b * x_c
            if not prod in uvectorc:
                uvectorc.append(prod)
                matc = matc.col_insert(nr_cols,zero_vec)
                nr_cols += 1
    return (matc, uvectorc)

# deprecated
def get_lone_vectors(kern_vec, kern_k, list_lones, uvector, nr_nonlones, bm_rows, bm_columns):
    offset_columns = bm_columns * nr_nonlones
    kern_vec_chunks = []
    for i in range(bm_rows):
        chunk = []
        for j in range(len(kern_k)):
            chunk.append(kern_vec[j + offset_columns])
        kern_vec_chunks.append(chunk)
        offset_columns += len(kern_k)
        
    kern_k_vec_for_each_row = []
    for i in range(bm_rows):
        vecs = []
        for j in range(len(kern_k)):
            vecs.append(kern_k[j] * kern_vec_chunks[i][j])
        sum_vec = vecs[0]
        for j in range(len(kern_k)-1):
            sum_vec = sum_vec.add(vecs[j+1])
        kern_k_vec_for_each_row.append(sum_vec)
    
    r_lones = []
    for k in list_lones:
        ctr_uvector = 0
        for mono in uvector:
            if mono == k:
                rvec = []
                for i in range(bm_rows):
                    rvec.append(kern_k_vec_for_each_row[i][ctr_uvector,0])
                rvec = Matrix([rvec])
                r_lones.append((k, rvec.transpose()))
            ctr_uvector += 1
    return r_lones
    
# deprecated
def get_nonlone_vectors(kern, bm_columns, list_nonlones):
    kern_vec = kern[0]
    kern_ran = [i + 1 for i in range(len(kern)-1)]
    for i in kern_ran:
        kern_vec = kern_vec.add(kern[i])
    rvectors_nonlone = []
    ctr = 0
    for k in list_nonlones:
        rvec = []
        for i in range(bm_columns):
            rvec.append(-kern_vec[ctr + i])
        rvec = Matrix([rvec]).transpose()
        rvectors_nonlone.append((k, rvec))
        ctr += bm_columns
    return (rvectors_nonlone, kern_vec)

# deprecated
def make_solution_matrix(benc_mats, kernel_k, uvectork, sublist_nonlones_k):
    bm_rows = shape(benc_mats[0][1])[0]
    bm_columns = shape(benc_mats[0][1])[1]
    kernel_k_length = len(kernel_k)
    nr_nonlones = len(sublist_nonlones_k)
    uvectork_sublist = []
    ctrmono = 0
    for mono in uvectork:
        if type(mono) != int:
            lis = []
            recovervars(mono,lis)
            if len(lis) == 2:
                if lis[0] in sublist_nonlones_k:
                    args = lis[0], lis[1]
                else:
                    args = lis[1], lis[0]
                uvectork_sublist.append((ctrmono, mono, args))
        ctrmono += 1
    nr_combos = len(uvectork_sublist)
    columns_sol_mat = nr_nonlones * bm_columns + kernel_k_length * bm_rows
    rows_sol_mat = bm_rows * nr_combos
    sol_mat = zeros(rows_sol_mat, columns_sol_mat)
    sol_list = []
    
    second_half_offset = nr_nonlones * bm_columns
    ctr_columns_nonlones_offset = 0
    ctr_rows_offset = 0
    for k in sublist_nonlones_k:
        for (ctr, mono, (kp, bx)) in uvectork_sublist:
            if kp == k:
                (mat_found, mat) = select_benc_mat(bx, benc_mats)
                if mat_found:
                    for i in range(bm_rows):
                        sol_list.append(mono)
                        for j in range(bm_columns):
                            sol_mat[i + ctr_rows_offset, j + ctr_columns_nonlones_offset] = mat[i,j]
                    
                    selected_kernel = []
                    for i in range(kernel_k_length):
                        selected_kernel.append(kernel_k[i][ctr])
                    
                    ctr_columns_offset2 = second_half_offset
                    for i in range(bm_rows):
                        for j in range(kernel_k_length):
                            sol_mat[i + ctr_rows_offset, j + ctr_columns_offset2] = selected_kernel[j]
                        ctr_columns_offset2 += kernel_k_length
                    ctr_rows_offset += bm_rows
        ctr_columns_nonlones_offset += bm_columns
    return (sol_list, sol_mat)

def add_rvectors_nonlone_kern_vec(rvectors_nonlone, kern_vec, rvectors_nonlone_new, kern_vec_new):
    kern_vec += kern_vec_new
    ctr = 0
    for (elem1, rvec1) in rvectors_nonlone:
        for (elem2, rvec2) in rvectors_nonlone_new:
            if elem1 == elem2:
                rvectors_nonlone[ctr] = (elem1, rvec1 + rvec2)
        ctr += 1
    return (rvectors_nonlone, kern_vec)

def select_benc_mat(bx, benc_mats):
    for (bxp, mat) in benc_mats:
        if bx == bxp and mat != None:
            return (True, mat)
    return (False, None)
    
def sublistslonenonlone(list_lone_nonlone):
    sublist_nonlones = []
    sublist_lones = []
    for (c,nonlone) in list_lone_nonlone:
        if nonlone:
            sublist_nonlones.append(c)
        else: 
            sublist_lones.append(c)
    return (sublist_nonlones, sublist_lones)
     
def unify_benc_mats(bm1, bm2):
    bm_new = []
    bm1_sh = shape(bm1[0][1])
    bm2_sh = shape(bm2[0][1])
    bm1_rows = bm1_sh[0]
    bm1_columns = bm1_sh[1]
    bm2_rows = bm2_sh[1]
    bm2_columns = bm2_sh[0]
    bm_max_rows = max(bm1_rows, bm2_rows)
    bm_max_columns = max(bm1_columns, bm2_columns)
    
    for (bx, bmat) in bm1:
        bmat_new = zeros(bm_max_rows, bm_max_columns)
        for i in range(bm1_rows):
            for j in range(bm1_columns):
                bmat_new[i,j] += bmat[i,j]
        bm_new.append((bx, bmat_new))
        
    for (bx, bmat) in bm2:
        bmat = bmat.transpose()
        bmat_new = zeros(bm_max_rows, bm_max_columns)
        for i in range(bm2_rows):
            for j in range(bm2_columns):
                bmat_new[i,j] += bmat[i,j]
        bm_new.append((bx, bmat_new))
    
    return bm_new

def construct_benc_mats(benc, nonlonesub, uvector, kern):
    benc_mats = []
    notinit_b = []
    for bx in benc:
        bx_not_in_benc = True
        bmat = [[0 for i in kern] for j in nonlonesub]
        count = 0
        for mono in uvector:
            if type(mono) != int:
                lis = []
                recovervars(mono,lis)
                if bx in lis and len(lis) == 2:
                    bx_not_in_benc = False
                    sindex = 1 - lis.index(bx)
                    svar = lis[sindex]
                    row_s = nonlonesub.index(svar)
                    count_kern = 0
                    for v in kern:
                        bmat[row_s][count_kern] = v.row(count)[0]
                        count_kern += 1
            count += 1
        if bx_not_in_benc:
            notinit_b.append(bx)
        else:  
            bmat = Matrix(bmat)
            benc_mats.append((bx,bmat))
    return (benc_mats, notinit_b)

def construct_lone_vects(benc, lonesub, uvector, kern, len_vec):
    lone_vects = []
    for slone in lonesub:
        svec = [0 for i in range(len_vec)]
        count = 0
        for mono in uvector:
            if type(mono) != int:
                lis = []
                recovervars(mono,lis)
                if slone in lis and len(lis) == 1:
                    row_s = lonesub.index(slone)
                    for i in range(len(kern)):                  
                        svec[i] = kern[i].row(count)[0]
            count += 1
        svec = Matrix([svec]) #.transpose()
        lone_vects.append((slone, svec))
    return lone_vects

def determine_non_lone_vars_in_uvector(enc, benc, uvector):
    list_non_common_vars = []
    for mono in uvector:
        if type(mono) != int:
            lis = []
            recovervars(mono,lis)        
            for x in lis:
                if not x in benc and not x in list_non_common_vars:
                    list_non_common_vars.append(x)
    list_nonlone = []
    for x in list_non_common_vars:
        non_lone = False
        for mono in uvector:
            if type(mono) != int:
                lis = []
                recovervars(mono,lis)
                if x in lis:
                    for y in lis:
                        if y in benc:
                            non_lone = True
        list_nonlone.append((x, non_lone))
    return list_nonlone

def check_kernel_products(masterkey, special_s, kenc, cenc, benc, unknown):
    kenc = canonical(kenc)
    cenc = canonical(cenc)
    
    penc = []
    for k_el in kenc:
        for c_el in cenc:
            penc.append(cancel(k_el*c_el))
    
    (mat,uvector) = writeencodingasprod(penc, unknown)
    
    BigMat = Matrix(mat)
    
    mk_index = 0
    ctr = 0
    for el in uvector:
        if el == masterkey * special_s:
            mk_index = ctr
        ctr += 1
    
    kern = BigMat.nullspace()
    
    eqs = []
    eqsfound = False
    for vec in kern:
        if vec[mk_index] != 0:
            eqsfound = True
            eqs.append(vec[mk_index])
    return (eqsfound, eqs)

if __name__ == "__main__":

    # Wat11

    alpha, b, bp, b0, b1, b2, r, rp, x, y, s, sp = symbols('alpha, b, bp, b0, b1, b2, r, rp, x, y, s, sp')

    k1 = alpha + r*b
    k2 = r*b0
    k3 = r
    c1 = s*b + sp*b1
    c2 = s
    c3 = sp
    c4 = s*b + sp*b2
    mpk1 = b0
    mpk2 = b1
    mpk3 = b
    mpk4 = 1
    mpk5 = b2
    
    # known values: x, y

    unknown = [alpha, b, b0, b1, b2, r, s, sp]

    k = [k1, k2, k3]
    c = [c1, c2, c3, c4]
    mpk = [mpk1, mpk2, mpk3, mpk5]

    # generate_the_proofs(alpha, s, k, c, mpk, unknown)
    # print(generate_proof_selective(k, c, mpk, unknown))
    
    # RW13

    alpha, b, bp, b0, b1, r, rp, x, y, s, sp = symbols('alpha, b, bp, b0, b1, r, rp, x, y, s, sp')

    k1 = alpha + r*b
    k2 = r*bp + rp*(b0 + y*b1)
    k3 = r
    k4 = rp
    c1 = s*b + sp*bp
    c2 = sp*(b0 + x*b1)
    c3 = s
    c4 = sp
    mpk1 = b0
    mpk2 = b1
    mpk3 = b
    mpk4 = bp
    
    # known values: x, y

    unknown = [alpha, b, b0, b1, bp, r, rp, s, sp]

    k = [k1, k2, k3, k4]
    c = [c1, c2, c3, c4]
    mpk = [mpk1, mpk2, mpk3, mpk4]
    
    pprint(generate_proof_selective(alpha, s, k, c, mpk, unknown))
