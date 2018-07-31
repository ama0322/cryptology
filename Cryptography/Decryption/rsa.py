from Cryptography import misc
import secrets # to generate random number to figure out the number of characters to read

# Cipher info:
char_set = misc.BINARY_TO_CHAR_ENCODING_SCHEMES
cipher_type = "asymmetric"
key_size = "multiple generated characters"






# Cipher settings:
key_bits = 2048



########################################################################################## STANDARD FUNCTIONS ##########


# Call the proper functions to decrypt. Return decrypted text bac to cryptography_runner.py
def execute(data, output_location):
    """
    This function decrypts data using a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the location to save relevant info into
    :return: (string) the decrypted data
    """

    # Decrypt the ciphertext. Write the plaintext and info to a file
    misc.execute_encryption_or_decryption(data, output_location, "Decryption", "rsa", "decrypt")





# Figure out the encryption and decryption code. Pass info to misc' testing_execute function
def testing_execute(encryption, decryption, plaintext, plaintext_source, encryption_key, encoding,
                    output_location):
    """
    Conducts an rsa decryption in testing mode

    :param encryption: (string) the name of the encryption cipher to use
    :param decryption: (string) the name of the decryption cipher to use (this)
    :param plaintext_source: (string) the location where the plaintext is found
    :param plaintext: (string) the plaintext to encrypt
    :param encryption_key: (string) the key to use to encrypt
    :param encoding: (str) the size of the character set to use
    :param output_location: (string) the name of the file to write statistics in
    :return: None
    """

    # Store statistics from the last encryption here(Just declarations):
    testing_execute.time_to_generate_keys = 0
    testing_execute.num_blocks = 0
    testing_execute.block_size = 0

    # Store statistics from the last decryption done here.

    # Encryption code
    encryption_code = \
    r"""new_file.writelines([
                             "\n\n\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                             "\n--------------- public key " 
                                + str(rsa.key_bits) + "-bit ---------------\n" 
                                + public_key 
                                + "\n-----------------------------------------------"
                                + "-------------------------------------" ,
                             "\n𝐓𝐢𝐦𝐞 𝐭𝐨 𝐠𝐞𝐧𝐞𝐫𝐚𝐭𝐞 𝐛𝐨𝐭𝐡 𝐤𝐞𝐲𝐬 (𝐟𝐢𝐠𝐮𝐫𝐢𝐧𝐠 𝐨𝐮𝐭 𝐭𝐰𝐨 𝐩𝐫𝐢𝐦𝐞𝐬): " 
                                + str(rsa.testing_execute.time_to_generate_keys) + " seconds",
                             "\n𝐓𝐡𝐞 𝐜𝐢𝐩𝐡𝐞𝐫𝐭𝐞𝐱𝐭'𝐬 𝐞𝐧𝐜𝐨𝐝𝐢𝐧𝐠 𝐬𝐜𝐡𝐞𝐦𝐞 𝐢𝐬: " + char_encoding_scheme_of(ciphertext),
                             "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧 these seconds: " 
                                + str(encryption_time - rsa.testing_execute.time_to_generate_keys) 
                                + " (s) with " + "{:,}".format(len(plaintext)) + " characters and " 
                                + "{:,}".format(rsa.testing_execute.num_blocks) 
                                + " blocks (" + str(rsa.testing_execute.block_size) + " characters each)",                        
                             "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " 
                                + str(((encryption_time - rsa.testing_execute.time_to_generate_keys) 
                                / len(plaintext)) * 1000000)
                                + " (μs)"
                            ])
    """

    # Decryption code
    decryption_code = \
    r"""new_file.writelines([
                             "\n\n\n𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                             "\n--------------- private key " + str(rsa.key_bits) 
                                + "-bit ---------------\n" + private_key 
                                + "\n---------------------------------------------"
                                + "---------------------------------------" ,
                             "\n𝐓𝐡𝐞 𝐩𝐥𝐚𝐢𝐧𝐭𝐞𝐱𝐭'𝐬 character set 𝐢𝐬: " + alphabet_of(ciphertext),
                             "\n𝐃𝐞𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧 these seconds: " + str(decryption_time) 
                                + " (s) with " + "{:,}".format(len(plaintext)) + " characters and "
                                + "{:,}".format(rsa.testing_execute.num_blocks) 
                                + " blocks (" + str(rsa.testing_execute.block_size) + " characters each)",                
                             "\n𝐓𝐢𝐦𝐞𝐬 𝐥𝐨𝐧𝐠𝐞𝐫 𝐭𝐡𝐚𝐧 𝐞𝐧𝐜𝐫𝐲𝐩𝐭𝐢𝐨𝐧: " 
                                + str(decryption_time/(encryption_time - 
                             rsa.testing_execute.time_to_generate_keys)) 
                                + " (times)",                             
                             "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str((decryption_time / len(plaintext)) * 1000000)
                                + " (μs)"
                            ])
    """

    misc.testing_execute_encryption_and_decryption(encryption, decryption,
                                                            plaintext, plaintext_source, encryption_key, encoding,
                                                            output_location,
                                                            "RSA",
                                                            encryption_code, decryption_code)






# Returns string. This is the actual algorithm to decrypt
def decrypt(ciphertext, private_key, encoding_scheme):
    """
    This function decrypts with rsa cipher

    :param ciphertext: (string) the ciphertext to decrypt
    :param private_key: (string) the key to decrypt with. In format "(encoding scheme) d = ..., n = ..."
    :param encoding_scheme: (string) the type of encoding scheme that is used
    :return: (string) the deciphered text
    """

    plaintext = "" # Build up the decrypted text here
    plaintext_blocks = [] # List of plaintext blocks
    block_size_bytes = 0 # The size of each rsa block (in bytes)
    d = 0 # The decryption number for decrypting
    n = 0 # The modulus number for encrypting




    # Figure out d and n from the private key
    d, n = read_rsa_key(private_key)



    # Figure out the number of characters to read (same as modulus' bit length). Generate a random integer that has
    # n.bit_length(), encode that, and count the length of the result
    randint = secrets.randbits(n.bit_length())
    block_size_len = len(misc.int_to_chars_encoding_scheme_pad(randint, encoding_scheme,
                                                                        n.bit_length()))



    # Read in the ciphertext in block_size_bytes. Turn each block into an integer using the correct encoding scheme.
    # Then, use the rsa cipher (on each block) of pow(c, d, n) in order to get the message m (in integer form). Turn
    # the integers into plaintext blocks(through utf-8 interpretation of the bytesarray). Then, concatenate all the
    # blocks together in order to get the full plaintext
    ciphertext_blocks  = []
    while ciphertext != "":
        ciphertext_blocks.append(ciphertext[0: block_size_len])
        ciphertext = ciphertext[block_size_len:]

    # Turn each block into an integer
    ciphertext_blocks = [ misc.chars_to_int_decoding_scheme(block, encoding_scheme)
                                                                                     for block in ciphertext_blocks]

    # Apply the rsa cipher on each integer to get the plaintext integer. Turn the number into byte
    for block in ciphertext_blocks:
        plaintext_blocks.append(pow(block, d, n))
        print("Decryption percent done: " + str((len(plaintext_blocks) / len(ciphertext_blocks)) * 100))


    # Turn each block number into hexadecimal string. Then, concatenate in one large string and then decode to utf-8
    # (through a bytearray interpretation)
    plaintext_blocks = [hex(block)[2:]  for block in plaintext_blocks]
    for block in plaintext_blocks:
        plaintext += block
    plaintext = bytearray.fromhex(plaintext).decode("utf-8")



    return plaintext




######################################################################################### ANCILLARY FUNCTIONS ##########




# Reads an rsa key and returns the public/private key and modulus
def read_rsa_key(key):
    """
    This reads the rsa key which is in the format of "RSA (character length of e or d) (e or d) n"

    :param key: (string) the rsa key
    :return: (int) the public/private exponent key
    :return: (int) the modulus for rsa
    """

    # Figure out the character scheme of the key
    scheme = misc.char_encoding_scheme_of(key)

    # Decode the key to format: "RSA (character length of e or d) (e or d) n"
    key = misc.chars_to_chars_decoding_scheme(key, scheme)


    # Figure out how many characters to read for the exponent d/e. From the first space to the second. Convert to int
    first_space_index = key.find(" "); second_space_index = key.find(" ", first_space_index + 1)
    length = key[ first_space_index + 1: second_space_index ]
    length = int(length, 10)

    # Read length characters to figure out e/d and also n. Decode them into ints
    exponent = key[ second_space_index + 1: second_space_index + 1 + length ]
    n = key[ second_space_index + 1 + length: ]
    exponent = misc.chars_to_int_decoding_scheme(exponent, scheme)
    n = misc.chars_to_int_decoding_scheme(n, scheme)

    # Return the exponent and the modulus
    return exponent, n

