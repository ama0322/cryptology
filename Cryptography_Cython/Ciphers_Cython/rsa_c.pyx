import secrets # To generate cryptographically secure primes
import random # To generate random numbers














# This function generates a pair of primes whose product is prime_bits long
cdef int generate_prime_pair_PrimesFound = 0
cdef int generate_prime_pair_NumbersTested = 0
cpdef tuple generate_prime_pair(int prime_bits):#region...
    """
    Figures out a pair of primes whose product is of size prime_bits. 
    
    When a prime is found, it is multiplied against all the primes in primes_list to try to find a pair that gives a 
    correct size key. If one is not found, this prime is added to the list, and a new prime number is searched for.
        
    :param prime_bits: (int) The size of the product of the two primes
    :return:           (int) One prime
    :return:           (int) Another prime
    """


    # Get access to the "static" variable
    global generate_prime_pair_PrimesFound
    global generate_prime_pair_NumbersTested


    # Useful variables
    cdef list primes_list = [generate_prime(prime_bits // 2)]  # List to store primes
    generate_prime_pair_PrimesFound += 1
    cdef int i = 1                                             # Looping variable
    prime_one = 0                                     # Store a prime here
    prime_two = 0                                     # Store another prime here


    # If prime_bits is odd, then, alternate between generating primes of half_length and half_length+1
    if prime_bits % 2 != 0:


        # Loop until two prime numbers are found whose product is the correct size (prime_bits)
        for i in range(1, 999999999999):

            # Alternate between generating primes of size (prime_bits // 2) and ((prime_bits // 2) + 1)
            if i % 2 == 0:
                prime_one = generate_prime(prime_bits // 2);       generate_prime_pair_PrimesFound += 1
            else:
                prime_one = generate_prime((prime_bits // 2) + 1); generate_prime_pair_PrimesFound += 1

            # Test all pairs of primes for a key that is of proper size
            for prime_two in primes_list:

                # If the primes work out to make a key of correct size
                if (prime_one * prime_two).bit_length() == prime_bits:
                    # Print updates, reset static_vars, and return
                    print ("\r{} numbers tested for primality. Primes found: {}"
                           .format("{:,}".format(generate_prime_pair_NumbersTested),
                                   "{:,}".format(generate_prime_pair_PrimesFound)   )),
                    generate_prime_pair_PrimesFound = 0
                    generate_prime_pair_NumbersTested = 0
                    return prime_one, prime_two

            # add this current prime into the list for testing
            primes_list.append(prime_one)

            print([prime.bit_length() for prime in primes_list])


    # Else, prime_bits is even, so this is straightforward. Just generate primes that are half the bit_length
    elif prime_bits % 2 == 0:


        # Loop until two prime numbers are found whose product is the correct size (prime_bits)
        while True:

            # Generate a prime for testing
            prime_one = generate_prime(prime_bits // 2); generate_prime_pair_PrimesFound += 1

            # Test all pairs of primes for a key that is of proper size
            for prime_two in primes_list:

                # If the primes work out to make a key of correct size
                if (prime_one * prime_two).bit_length() == prime_bits:

                    # Print updates, reset static_vars, and return
                    print ("\r{} numbers tested for primality. Primes found: {}"
                           .format("{:,}".format(generate_prime_pair_NumbersTested),
                                   "{:,}".format(generate_prime_pair_PrimesFound)   )),
                    generate_prime_pair_PrimesFound = 0
                    generate_prime_pair_NumbersTested = 0
                    return prime_one, prime_two

            # add this current prime into the list for testing
            primes_list.append(prime_one)






#endregion









# This generates a prime of bit_length
cdef list generate_prime_SmallPrimes = [
                #region...
                2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
                103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
                211,
                223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
                337,
                347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457,
                461,
                463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
                601,
                607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
                739,
                743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
                881,
                883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019,
                1021,
                1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123,
                1129,
                1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259,
                1277,
                1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399,
                1409,
                1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
                1511,
                1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619,
                1621,
                1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753,
                1759,
                1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889,
                1901,
                1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027,
                2029,
                2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143,
                2153,
                2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293,
                2297,
                2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411,
                2417,
                2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557,
                2579,
                2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693,
                2699,
                2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803,
                2819,
                2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957,
                2963,
                2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109,
                3119,
                3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257,
                3259,
                3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389,
                3391,
                3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533,
                3539,
                3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659,
                3671,
                3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797,
                3803,
                3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929,
                3931,
                3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079,
                4091,
                4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229,
                4231,
                4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363,
                4373,
                4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517,
                4519,
                4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
                4663,
                4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801,
                4813,
                4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967,
                4969,
                4973, 4987, 4993, 4999
                #endregion
            ]
cdef generate_prime(bit_length):#region...
    """
    This function returns a large prime number of bit_length size. This works by producing a random number
    that is of size bit_length(in base 10). Then, the number is tested for primality. This is done by testing
    its compositeness with several small prime numbers to immediately rule out many composite numbers. If the
    number then passes that test, then the rabin-miller test is run up to 64 times to rule out composite. The
    returned number then has a very high probability that it is a prime number.

    :param bit_length: (int) the bit length of the generated prime
    :return:           (int) the generated prime number
    """


    # Get "static variables"
    global generate_prime_pair_NumbersTested
    global generate_prime_pair_PrimesFound


    # Useful variables
    cdef int failed_prime = 0
    candidate = 0


    # Loop until a prime number has been generated
    while True:

        # Generate a number that needs to be tested for primality
        candidate = secrets.randbits(bit_length - 1) ^ (1 << (bit_length - 1))

        # Print updates and update
        print ("\r" + str(generate_prime_pair_NumbersTested) + " numbers tested for primality. Primes found: "
                    + str(generate_prime_pair_PrimesFound)),
        generate_prime_pair_NumbersTested += 1

        # Set the lowest bit to 1 to make the number odd
        candidate = candidate | 1

        # While small primes test fails, update number with += 2 and test again
        failed_prime = small_primes_primality_test(candidate)
        while failed_prime != 0:
            # Print updates
            print ("\r" + str(generate_prime_pair_NumbersTested) + " numbers tested for primality. Primes found: "
                        + str(generate_prime_pair_PrimesFound)),
            generate_prime_pair_NumbersTested += 1

            # Update the number, and run small primes test again
            candidate += 2
            failed_prime = small_primes_primality_test(candidate)

        # If the number is too large (highly unlikely), then generate new number
        if failed_prime.bit_length() > bit_length:
            continue



        # If failed fermat's little theorem, then generate new number
        if fermat_primality_test(candidate) == False:
            continue



        # If the generated number was prime, then return. Otherwise, loop again until found prime
        if rabin_miller_primality_test(candidate):
            return candidate


#endregion






# Small primes primality test
cdef int small_primes_primality_test(candidate):#region...
    """
    Tests if small primes divide into this candidate. 
        
    :param candidate: (int) The number to test
    :return:          (int) The small prime that causes candidate to fail. (Returns 0 if passed)
    """

    # Check that number not evenly divisible by small primes
    cdef int prime
    for prime in generate_prime_SmallPrimes:
        if candidate % prime == 0:
            return prime

    # All the small primes have been checked, so the number passes the small primes test
    return 0



#endregion

# Fermat primality test
cdef bint fermat_primality_test(candidate):#region...
    """
    Uses fermat's little theorem to rule out many composite numbers. Fermat's primality test is probabalistic.
        
    Fermat's little theorem states that if p is prime and a is not divisible by p, then:
        pow(a, p - 1, p) == 1 where "a" is not divisible by "p"

        
    :param candidate: (int)  The number to test
    :return:          (bool) If the number is prime 
    """

    # FERMAT'S LITTLE THEOREM: First, find "a" where "1 > a > candidate" and "candidate not divisible by a"
    a = secrets.randbelow(candidate - 1)  # Get a number to test with


    # Return test results
    return pow(a, candidate - 1, candidate) == 1
#endregion

# Rabin miller primality test
cdef bint rabin_miller_primality_test(candidate):#region...
    """
    Runs rabin_miller test on candidate. Although rabin_miller is probabilistic, the test is run so many times, the 
    test is almost 100% accurate. 
        
    :param candidate: (int)  The number to test for primality
    :return:          (bool) If the number is prime 
    """



    # Useful variables
    cdef int i      = 0      # Looping variable
    result = 0               # Rabin-miller variable


    # Setup for rabin miller
    s = candidate - 1
    cdef int power = 0
    while s % 2 == 0:
        s = s // 2
        power += 1

    # Run the rabin miller test however many times
    cdef int trials = 0
    while trials < 64:

        result = pow(random.randrange(2, candidate - 1), s, candidate)

        # Test does not apply for result == 1. Try again with a different base
        if result == 1:
            continue

        # Check if the number is composite
        while result != (candidate - 1):

            # At this point, the number is composite
            if i == power - 1:
                return False

            # Not proven to be composite, so move to next iteration
            else:
                i = i + 1
                result = (result ** 2) % candidate

        # Passed one rabin-miller test. Move onto the next one
        trials += 1

    # passed all tests, so almost definitely prime
    return True

#endregion















































