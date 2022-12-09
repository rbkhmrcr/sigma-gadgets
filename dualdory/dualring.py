#!/usr/bin/env python
# coding: utf-8

import os
import secrets
import time
import numpy as np
from sympy import mod_inverse
from decimal import Decimal
from math import log2
from pprint import pprint
# if having trouble importing Crypto, try uninstall Crypto and install Cryptodome instead
from Crypto.Hash import SHA256
from fastecdsa import keys, curve, ecdsa
from hashlib import sha256, sha512, sha384

# define basic parameter
my_curve = curve.P256
g = my_curve.G
p = my_curve.q
generator_u = g * secrets.randbelow(p)


# define basic operation
# int(c, 16) is to convert hexadecmical strings to actual numbers, I don't think it would limit the size of the number
def A(r):
    return g * r
def Z(sk,r,c):
    c = int(c, 16)
    return (r - c*sk) % p
def Z1(sk,r,c):
    return (r - c*sk) % p
def V1(z):
    return g * z
def V2(pk, c):
    c = int(c, 16)
    return pk*c
def V_z(z, pk, c):
    c = int(c, 16)
    return (g*z) + (pk*c)
    
# setup function, not actually called since parameter are already defined
def Setup(parameter):
    return parameter, hash


# key generation calling ecc keyGen
def KeyGen():
#     sk is before pk
    return keys.gen_keypair(my_curve)


# converting a ecc point to string form: taking its x and y coodinates
def pt_to_string(point):
    a = str(point.x)
    b = str(point.y)
    return a + b
    
# algorithm 1: Schnorr signature
# not for ring signature
def SIGN(m, sk):
    r = secrets.randbelow(p)
    R = A(r)
    my_string = m + pt_to_string(R)
    c = sha256(my_string.encode()).hexdigest()
    z = Z(sk,r,c)
    return z, c

def VERIFY(m, pk, sigma):
    z = sigma[0]
    c = sigma[1]
    R_prime = V_z(z, pk, c)
    my_string = m + pt_to_string(R_prime)
    x = sha256(my_string.encode()).hexdigest()
    if c != sha256(my_string.encode()).hexdigest():
        return 0
    return 1


for i in range (100):
    sk_temp, pk_temp = KeyGen()
    s = SIGN("i am ", sk_temp)
    if (VERIFY("i am ", pk_temp, s) == 0):
        print("failed")
        break  

# helper method to convert a list of numbers to a string
def list_to_string(l):
    a = ''
    for i in range (len(l)):
        a = a + str(l[i])
############################################# set a = hash(a) before returning it #######  
    return a
    
# (Sign, Verify) is the ring signature scheme of AOS ring signature in Asiacrypt 2002 (Schnorr-based)
# assume PK is an array of public keys pk1, pk2,...,pkn
# j is the location of the pk corresponding to sk; note the list starts at 0 instead of 1
def Sign(m, PK, sk, j):
    universal_pk_string = list_to_string(PK)
################### compute m + universal_pk_string here instead of doing it in for loop every time #####
    r = secrets.randbelow(p)
    R_array = [None] * len(PK)
    c_array = [None] * len(PK)
    z_array = [None] * len(PK)
    R_array[j] = A(r)
    for i in range (j + 1, len(PK)):
        my_string = m + universal_pk_string + pt_to_string(R_array[i - 1])
        c_array[i] = sha256(my_string.encode()).hexdigest()
        z_array[i] = secrets.randbelow(p)
        R_array[i] = V_z(z_array[i], PK[i], c_array[i])
    for ii in range (0, j):
######################################## why is it range from 0 to j, not 0 to j-1? Is it correct ######
        if ii == 0:
            my_string = m + universal_pk_string + pt_to_string(R_array[len(PK) - 1])
            c_array[ii] = sha256(my_string.encode()).hexdigest()
        else:
            my_string = m + universal_pk_string + pt_to_string(R_array[ii - 1])
            c_array[ii] = sha256(my_string.encode()).hexdigest()
        z_array[ii] = secrets.randbelow(p)
        R_array[ii] = V_z(z_array[ii], PK[ii], c_array[ii])
    this_string = m + universal_pk_string + pt_to_string(R_array[j - 1])
    c_array[j] = sha256(this_string.encode()).hexdigest()
    z_array[j] = Z(sk, r, c_array[j])
    return (c_array[0], z_array)


def Verify(m, PK, sigma):
    universal_pk_string = list_to_string(PK)
################### compute m + universal_pk_string here instead of doing it in for loop every time #####
    c = sigma[0]
    z_array = sigma[1]
    R_array = [None] * len(PK)
    R_array[0] = V_z(z_array[0], PK[0], c)
    n = len(PK)
    for i in range (1, n):
        my_string = m + universal_pk_string + pt_to_string(R_array[i - 1])
        temp_c = sha256(my_string.encode()).hexdigest()
        R_array[i] = V_z(z_array[i], PK[i], temp_c)
    compare_string = m + universal_pk_string + pt_to_string(R_array[n - 1])
    d = sha256(compare_string.encode()).hexdigest()
    if c != d:
        print('AOS signature verification failed')
        return 0
    return 1



# testing
PK_num = 20
for ii in range (0, 20):
    fake_PK = [None]* (PK_num)
    for i in range (0, PK_num):
    #     fill it with fake first, then change later
        foo, fake_PK[i] = KeyGen()
    ssk, ppk = KeyGen()
    my_sk, fake_PK[ii] = ssk, ppk
    hh = Sign("I am ", fake_PK, my_sk, ii)
    if Verify("I am ", fake_PK, hh) != 1:
        print ("failed")

# DL-based DualRing Sign without calling the NISA function
# signature size is O(n)
def basic_sign(m, pk_list, sk, j):
    r = secrets.randbelow(p)
    c_array = [None] * len(pk_list)
    universal_pk_string = list_to_string(pk_list)
    R = g * r
    summation_except_j = 0
    for i in range (len(pk_list)):
        if i == j:
            continue
        temp_c = secrets.randbelow(p)
        c_array[i] = temp_c
        R = R + (pk_list[i]* temp_c)
        summation_except_j = (summation_except_j + temp_c) 
    my_string = m + universal_pk_string + pt_to_string(R)
    C = sha256(my_string.encode()).hexdigest()
    C_number = int(C, 16) % p
#     with mod p won't work
    c_array[j] = (C_number - summation_except_j) % p
    z = Z1(sk,r,c_array[j])
    
#     testing time
#     log_2_len = int(log2(len(pk_list)))
#     basic_sign_time[log_2_len] = time.time() - start_time
    
    return c_array, z, C_number, R

# DL-based DualRing Verify without calling the NISA function
def basic_verify(m, pk_list, sigma):
#     start_time = time.time()
    c_array = sigma[0]
    universal_pk_string = list_to_string(pk_list)
    z = sigma[1]
    R = g * z
    for i in range (len(pk_list)):
        R = R + (pk_list[i]* c_array[i])
    my_string = m + universal_pk_string + pt_to_string(R)
    result = (int(sha256(my_string.encode()).hexdigest(), 16)) % p
    if (sum(c_array)) % p != result:
        print("basic verify failed")
        return 0
#     print('basic verify time elaspsed ', time.time() - start_time)

#     testing time
#     log_2_len = int(log2(len(pk_list)))
#     basic_verify_time[log_2_len] = time.time() - start_time
    return 1


PK_num = 20
for ii in range (0, 20):
    fake_PK = [None]* (PK_num)
    for i in range (0, PK_num):
    #     fill it with fake first, then change later
        foo, fake_PK[i] = KeyGen()
    ssk, ppk = KeyGen()
    my_sk, fake_PK[ii] = ssk, ppk
    hh = basic_sign("I am ", fake_PK, my_sk, ii)
    if basic_verify("I am ", fake_PK, hh) != 1:
        print ("failed")



power_of_2 = 10
PK_num = 2 ** power_of_2
time_trail = 1
fake_PK = [None]* (PK_num)
for i in range (0, PK_num):
#     fill it with fake first, then change later
    foo, fake_PK[i] = KeyGen()
ssk, ppk = KeyGen()
for ii in range (time_trail):
    start_time = time.time()
    random_position = secrets.randbelow(PK_num)
    my_sk, fake_PK[random_position] = ssk, ppk
    hh = basic_sign("foo", fake_PK, my_sk, random_position)
    basic_verify("foo", fake_PK, hh)
    print('total time elaspsed ', time.time() - start_time)
    
# pk_list: public key list
# u: another generator
# b: at first a list of 1s
# a: list of all c in algorithm 4
# Loop in NISA Proof
def P_proof(pk_list, this_u, b, a, L, R):
#     start_time = time.time()
    n = len(a)
#     additional check
#     if len(a) != len(b) or len(a) != len(pk_list):
#         print("len check failed")
    if n == 1:
        return (L, R, a, b)
    
    n_prime = int(n / 2)
#     c_L and c_R should be two scalars
    c_L = 0
    c_R = 0
    for i in range (n_prime):
        c_R += ((a[n_prime + i] * b[i]) % p)
        c_L += ((a[i] * b[n_prime + i]) % p)
    
#     my_L and my_R should be two pts on ECC
    my_L = this_u * c_L
    my_R = this_u * c_R

#     print('stage 1 time: ', time.time() - start_time)
#     start_time = time.time()
    
    for ii in range (n_prime):
        my_L = my_L + (pk_list[n_prime + ii] * a[ii])
        my_R = my_R + (pk_list[ii] * a[n_prime + ii])
    L.append(my_L)
    R.append(my_R)
    my_string = pt_to_string(my_L) + pt_to_string(my_R)
    
#     print('stage 2 time: ', time.time() - start_time)
#     start_time = time.time()
    
#     x should be a number
    x = int(sha256(my_string.encode()).hexdigest(), 16)
#     pk_prime_list is g' in the algorithm
    pk_prime_list = [None] * n_prime
#     b_prime_list = [None] * n_prime
    a_prime_list = [None] * n_prime

    x_inverse = mod_inverse(x, p)
#    print('current x', x)
#    print('x_inverse ', x_inverse)
#   b[i] for every i in range should be the same value
    b_value = (x_inverse * b[0] + x * b[n_prime]) % p
    b_prime_list = [b_value] * n_prime
    for iii in range (n_prime):
        pk_prime_list[iii] = pk_list[iii] * x_inverse + pk_list[n_prime + iii] * x
        a_prime_list[iii] = (x * a[iii] + x_inverse * a[n_prime + iii]) % p
#        b_prime_list[iii] = (x * b[n_prime + iii] + x_inverse * b[iii]) % p
#     print('stage 3 time: ', time.time() - start_time)
#     start_time = time.time()
    
#     recursion
    return P_proof(pk_prime_list, this_u, b_prime_list, a_prime_list, L, R)



# helper method to check if (i -1)'s jth bit is a 1
def check_bit(i, j):
    temp = i
    if ((temp >> j) & 1) == 1:
        return 1
    return -1




# b: at first a list of 1s
# c is the summation of ci in DualRing
# pi: the returned product from P
# Loop in NISA Verify
def V(pk_list, this_u, P, pi):
    L = pi[0]
    R = pi[1]
    a = pi[2][0]
    b = pi[3][0]

    original_length = len(pk_list)
    log_length = int(log2(original_length))
    x_list = [None] * log_length
#     x_list is a list of hashed numbers
    for i in range (log_length):
        my_string = pt_to_string(L[i]) + pt_to_string(R[i])
        x_list[i] = int(sha256(my_string.encode()).hexdigest(), 16)
#        print('current x', x_list[i])
    y_list = [None] * original_length
#     y is a list of numbers 
    for ii in range (original_length):
        product = 1
        for iii in range (log_length):
            if check_bit(ii, iii) == 1:
                product = (product * x_list[log_length - iii - 1]) % p
            else:
                inverse = mod_inverse(x_list[log_length - iii - 1], p)
                product = (product * inverse) % p
        y_list[ii] = product
    g_prime = pk_list[0] * y_list[0]
    for iv in range (1, original_length):
        g_prime = g_prime + (pk_list[iv] * y_list[iv])
    left_check = P
    for v in range (log_length):
######################## (x_list[v] ** 2) % p is computed twice. Store it in a variable and reuse it ##########
        x_sq = (x_list[v] ** 2) % p
        left_check = left_check + (L[v] * x_sq)
        left_check = left_check + (R[v] * mod_inverse(x_sq, p))
    right_check = (g_prime + this_u * b)*a
    if left_check == right_check:
        return 1
    return 0


# P: a point on ECC
# a: a list of all Cs
def NISA_Proof(pk_list, P, c, a):
    my_string = pt_to_string(P) + pt_to_string(generator_u) + str(c)
    h = int(sha256(my_string.encode()).hexdigest(), 16)
    uprime = generator_u * h
    b = [1] * len(a)
    return P_proof(pk_list, uprime, b, a, [], [])


def NISA_Verify(pk_list, P, c, pi):
    my_string = pt_to_string(P) + pt_to_string(generator_u) + str(c)
    h = int(sha256(my_string.encode()).hexdigest(), 16)
    uprime = generator_u * h
    P_prime = P + uprime * c
    return V(pk_list, uprime, P_prime, pi)


def full_Sign(m, pk_list, sk, j):
    start_time = time.time()
    sigma = basic_sign(m, pk_list, sk, j)
    c_array = sigma[0]
    z = sigma[1]
    c = sigma[2]
    R = sigma[3]
    P = R - (g * z)
#    print("c_array", c_array)
    pi = NISA_Proof(pk_list, P, c, c_array)
#    product = pk_list[0] * c_array[0]
#    for i in range (len(pk_list) - 1):
#        product = product + pk_list[i + 1] * c_array[i + 1]
#    print("product: ", product)
# P is not actually needed but just for the test sake

    print('sign time elaspsed ', time.time() - start_time)
    return c, z, R, pi, P


def full_Verify(m, pk_list, sigma):
    start_time = time.time()
    c = sigma[0]
    z = sigma[1]
    R = sigma[2]
    pi = sigma[3]
    P = R - (g * z)
    if NISA_Verify(pk_list, P, c, pi) == 0:
        print("NISA CHECK FAILED")
        return 0
    my_string = m + list_to_string(pk_list) + pt_to_string(R)
    check = int(sha256(my_string.encode()).hexdigest(), 16)
    if c == check:
        print('verify time elaspsed ', time.time() - start_time)
        return 1
    print("other check failed")
    return 0
    
# testing 
basic_sign_time_list = []
basic_verify_time_list = []
basic_entire_time_list = []
full_sign_time_list = []
full_verify_time_list = []
full_entire_time_list = []
algo2_sign_time_list = []
algo2_verify_time_list = []
algo2_entire_time_list = []
for power in range (12):
    power_of_2 = power + 1
    PK_num = 2 ** power_of_2
    time_trail = 1
    fake_PK = [None]* (PK_num)
    for i in range (0, PK_num):
    #     fill it with fake first, then change later
        foo, fake_PK[i] = KeyGen()
    ssk, ppk = KeyGen()
    for ii in range (time_trail):
        start_time = time.time()
        random_position = secrets.randbelow(PK_num)
        my_sk, fake_PK[random_position] = ssk, ppk
    
#     full sign part time record
        full_sign_time = time.time()
        hh = full_Sign("foo", fake_PK, my_sk, random_position)
        full_sign_time_list.append(time.time() - full_sign_time)
        full_verify_time = time.time()
        full_Verify("foo", fake_PK, hh)
        full_verify_time_list.append(time.time() - full_verify_time)
        full_entire_time_list.append(time.time() - start_time)
    
#     basic sign part time record
        start_time = time.time()
        basic_sign_time = time.time()
        hh = basic_sign("foo", fake_PK, my_sk, random_position)
        basic_sign_time_list.append(time.time() - basic_sign_time)
        basic_verify_time = time.time()
        basic_verify("foo", fake_PK, hh)
        basic_verify_time_list.append(time.time() - basic_verify_time)
        basic_entire_time_list.append(time.time() - start_time)
        
#       algorithm 2 sign part time record
        start_time = time.time()
        algo2_sign_time = time.time()
        hh = Sign("foo", fake_PK, my_sk, random_position)
        algo2_sign_time_list.append(time.time() - algo2_sign_time)
        algo2_verify_time = time.time()
        Verify("foo", fake_PK, hh)
        algo2_verify_time_list.append(time.time() - algo2_verify_time)
        algo2_entire_time_list.append(time.time() - start_time)
        
# more testing
algo2_sign_time_list = []
algo2_verify_time_list = []
algo2_entire_time_list = []
print(type(full_sign_time))
for power in range (12):
    power_of_2 = power + 1
    PK_num = 2 ** power_of_2
    time_trail = 1
    fake_PK = [None]* (PK_num)
    for i in range (0, PK_num):
    #     fill it with fake first, then change later
        foo, fake_PK[i] = KeyGen()
    ssk, ppk = KeyGen()
    for ii in range (time_trail):
        start_time = time.time()
        random_position = secrets.randbelow(PK_num)
        my_sk, fake_PK[random_position] = ssk, ppk
#       algorithm 2 sign part time record
        start_time = time.time()
        algo2_sign_time = time.time()
        hh = Sign("foo", fake_PK, my_sk, random_position)
        algo2_sign_time_list.append(time.time() - algo2_sign_time)
        algo2_verify_time = time.time()
        Verify("foo", fake_PK, hh)
        algo2_verify_time_list.append(time.time() - algo2_verify_time)
        algo2_entire_time_list.append(time.time() - start_time)



print(basic_sign_time_list)
print(basic_verify_time_list)
print(basic_entire_time_list)
print(full_sign_time_list)
print(full_verify_time_list)
print(full_entire_time_list)
print(algo2_sign_time_list)
print(algo2_verify_time_list)
print(algo2_entire_time_list)




# writing to file
with open("Ring Signature Time Analysis.txt", "w") as text_file:
    text_file.write("Power of 2\tFULL SIGN\tFULL VERIFY\n")
    for i in range (len(basic_sign_time_list)):
        text_file.write("%d\t%s\t%s\n" % (i + 1, full_sign_time_list[i] * 1000,  full_verify_time_list[i] * 1000))
