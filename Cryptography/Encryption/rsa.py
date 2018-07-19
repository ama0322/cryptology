from Cryptography import misc
import time                                      # To measure the amount of time for finding a public key
from Cryptography.Decryption import rsa          # RSA cipher info and read_rsa_key()


# Encrypt using user-entered info. Write relevant information and return encrypted text for cryptography_runner
def execute(data, output_location):
    """
    This function calls the appropriate functions in misc.py. Those functions will use the encrypt() function
    located below as the algorithm to actually encrypt the text. Then, the ciphertext will be returned back to
    cryptography_runner.py

    :param data: (string) the data to be encrypted
    :param output_location: (string) the location to print out the information
    :return: (string) the encrypted data
    """

    # Encrypt the plaintext. Print out the ciphertext and relevant information
    misc.execute_encryption_or_decryption(data, output_location,
                                                   "Encryption", "rsa", "encrypt")







# The actual algorithm to encrypt using rsa encryption
def encrypt(plaintext, given_key, encoding_scheme):
    """
    This encrypts using an rsa encryption. Random primes for the key are generated.

    :param plaintext: (string) the data to be encrypted
    :param given_key: (string) the public key used for encryption (not a requirement)
    :param key: (string) NOT USED
    :param encoding_scheme: (string) the name of the encoding scheme to use
    :return: (string) the encrypted text
    :return: (string) the generated public key for this in string form
    :return: (string) the generated private key for this in string form
    """

    key_size = rsa.key_bits      # the bit size of the key (needs to be divisible by 8)
    ciphertext = ""              # the string to build up the encrypted text
    prime_num_one = 0            # one of the randoly generated prime numbers
    prime_num_two = 0            # the other randomly generated prime numbers
    public_key = ""              # Store public key here
    private_key = ""             # Store private key here
    e = 0                        # the public encryption key (the actual number)
    d = 0                        # the private encryption key (the actual number)
    n = 0                        # the modulus for the encryption  (the number)


    # If the public key (given_key) not given, then generate public and private keys
    if given_key == "":

        # Generate two prime numbers that when multiplied together results in n with bit_length() of key_size. Two
        # prime numbers of size prime_bit_length may not necessarily result in a key_size of the 2 * prime_bit_length
        start_time = time.time()
        prime_one, prime_two = misc.get_prime_pair(key_size); rsa.testing_execute.time_to_generate_keys = \
                                                                                               time.time() - start_time


        # Calculate the public key and the private key
        e, d, n, public_key, private_key = _calculate_public_and_private_key(prime_one, prime_two, encoding_scheme)

    # Else, parse public_key to figure out e and n.
    else:
        e, n = rsa.read_rsa_key(given_key)
        public_key = given_key




    # Convert the plaintext into a long string of hex digits (through utf-8 interpretation). Divide the hex digits
    # into blocks of key_size // 8 bytes (the maximum that rsa can encrypt). Turn each of those hex blocks into
    # integers, and encrypt them each. Lastly, transform each of those ints into characters thorugh a character
    # encoding scheme, and concatenate the results together to get the ciphertext
    plaintext = plaintext.encode("utf-8").hex()


    # Divide the hexadecimal digits of plaintext into key_size//8 blocks. Store blocks in a list. Store num of blocks
    plaintext_blocks = []
    while plaintext != "":
        plaintext_blocks.append( plaintext[0: key_size // 8] )
        plaintext = plaintext[key_size // 8:]
    rsa.testing_execute.num_blocks = len(plaintext_blocks)

    # Turn each plaintext block from a string of hex digits into an integer
    plaintext_blocks = [int(block, 16) for block in plaintext_blocks]

    # For each block, run encryption with public key e. Then, turn the ciphertext number into characters with the
    # chosen character scheme
    ciphertext_blocks = [ pow(block, e, n) for block in plaintext_blocks ]
    ciphertext_blocks = [ misc.int_to_chars_encoding_scheme_pad(block, encoding_scheme, key_size)
                          for block in ciphertext_blocks] ;
    rsa.testing_execute.block_size = (len(ciphertext_blocks[0]))


    # Concatenate all of the blocks to form the ciphertext
    for block in ciphertext_blocks:
        ciphertext += block



    return ciphertext, public_key, private_key








def _calculate_public_and_private_key(prime_one, prime_two, encoding_scheme):
    """
    Given two primes, calculate the private and public key

    :param prime_one: (int) a prime
    :param prime_two: (int) another prime
    :param encoding_scheme: (string) tells us which character set to use to render the public/private
    keys as text
    :return: (int) encryption number e
    :return: (int) decryption number d
    :return: (int) modulus number n
    :return: (string) public key in format "e = ..., n = ..."
    :return:(string) private key in format "d = ..., n = ..."
    """
    two_bytes = 16
    modulus = prime_one * prime_two  # Calculate hte modulus by multiplying the two primes together
    modulus_totient = (prime_one - 1) * (
            prime_two - 1)  # Calculate totient speedily(using properties of primes)

    e = 65537  # Commonly used as e for low hamming weight, among other reasons

    # Calculate d (modular multiplicative inverse of (e mod n). Compute with extended euclidean algorithm
    def inverse(x, modulus):

        # Extended euclidean algorithm
        a, b, u = 0, modulus, 1
        while x > 0:
            # Figure out the integer quotient
            quotient = b // x

            # Update for next iteration
            x, a, b, u = b % x, u, x, a - (quotient * u)

        # Calculate the modular multiplicative inverse by a % m
        if b == 1:
            return a % modulus
    d = inverse(e, modulus_totient)

    # Save integer values of e, d, and modulus for return
    e_num = e
    d_num = d
    modulus_num = modulus

    # Convert d  and e, and modulus from numbers to encoded character version. Also do e and d's lengths
    e = misc.int_to_chars_encoding_scheme(e, encoding_scheme)
    e_len = len(e)
    d = misc.int_to_chars_encoding_scheme(d, encoding_scheme)
    d_len = len(d)
    modulus = misc.int_to_chars_encoding_scheme(modulus, encoding_scheme)

    # Build up the public and private keys strings. Then encode them using whichever scheme
    public_key = "RSA: " + str(e_len) + " " + e + modulus
    private_key = "RSA: " + str(d_len) + " " + d + modulus
    public_key = misc.chars_to_chars_encoding_scheme(public_key, encoding_scheme)
    private_key = misc.chars_to_chars_encoding_scheme(private_key, encoding_scheme)

    # Return the public and private keys
    return e_num, d_num, modulus_num, public_key, private_key









