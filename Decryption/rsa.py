import miscellaneous
import time # For timing to write relevant information into files
import secrets # to generate random number to figure out the number of characters to read



# Store statistics from teh last encryption done here
time_to_generate_keys = 0
key_bits = 0
num_blocks = 0
block_size = 0

# Store statistics from the last decryption done here



# Call the proper functions to decrypt. Return decrypted text bac to cryptography_runner.py
def execute(data, output_location):
    """
    This function decrypts data using a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the location to save relevant info into
    :return: (string) the decrypted data
    """

    # Obtain the decrypted text. Also write statistics and relevant info to a file
    decrypted = miscellaneous.asymmetric_decrypt_with_key(data, output_location, "Decryption", "rsa", "decrypt")

    # Return encrypted text to be written in cryptography_runner
    return decrypted





# Decrypt in testing mode. So add more statistics about performance. Check for correctness. Called from test.py
def testing_execute(ciphertext, output_location, plaintext, public_key, private_key, char_set_size, encryption_time):
    """
    Decrypt and save statistics.

    :param ciphertext: (string) the encrypted text to decipher
    :param output_location: (string) the file to save statistics into
    :param plaintext: (string) the original plaintext
    :param public_key: (string) the public key
    :param private_key: (string_ the private key
    :param char_set_size: (integer) the character set used
    :param encryption_time: (double) the time it took to encrypt using vigenere
    :return: None
    """

    # Encryption code
    encryption_code = \
    r"""new_file.writelines([
                             "\n\n\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                             "\n--------------- public key " + str(rsa.key_bits) + "-bit ---------------\n" + 
                             public_key +
                             "\n------------------------------------------------------------------------------------" ,
                             "\n𝐓𝐢𝐦𝐞 𝐭𝐨 𝐠𝐞𝐧𝐞𝐫𝐚𝐭𝐞 𝐛𝐨𝐭𝐡 𝐤𝐞𝐲𝐬 (𝐟𝐢𝐠𝐮𝐫𝐢𝐧𝐠 𝐨𝐮𝐭 𝐭𝐰𝐨 𝐩𝐫𝐢𝐦𝐞𝐬): " 
                             + str(rsa.time_to_generate_keys) + " seconds",
                             "\n𝐓𝐡𝐞 𝐜𝐢𝐩𝐡𝐞𝐫𝐭𝐞𝐱𝐭'𝐬 𝐞𝐧𝐜𝐨𝐝𝐢𝐧𝐠 𝐬𝐜𝐡𝐞𝐦𝐞 𝐢𝐬: " + char_encoding_scheme_of(ciphertext),
                             "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(encryption_time - rsa.time_to_generate_keys) 
                             + " seconds with " + "{:,}".format(len(plaintext)) + " characters and " 
                             + "{:,}".format(rsa.num_blocks) + " blocks (" + str(rsa.block_size) 
                             + " characters each)",                             
                             "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " 
                             + str(((encryption_time - rsa.time_to_generate_keys) / len(plaintext)) * 1000000), 
                             "\n𝐌𝐢𝐥𝐥𝐢𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " 
                             + str(((encryption_time - rsa.time_to_generate_keys)/ len(plaintext)) * 1000) 
                            ])
    """

    # Decryption code
    decryption_code = \
    r"""new_file.writelines([
                             "\n\n\n𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                             "\n--------------- private key " + str(rsa.key_bits) + "-bit ---------------\n" + 
                             private_key +
                             "\n------------------------------------------------------------------------------------" ,
                             "\n𝐓𝐡𝐞 𝐩𝐥𝐚𝐢𝐧𝐭𝐞𝐱𝐭'𝐬 character set 𝐢𝐬: " + char_set_of_ciphertext(ciphertext),
                             "\n𝐃𝐞𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(decryption_time) 
                             + " seconds with " + "{:,}".format(len(plaintext)) + " characters and "
                             + "{:,}".format(rsa.num_blocks) + " blocks (" + str(rsa.block_size) 
                             + " characters each)",                
                             "\n𝐓𝐢𝐦𝐞𝐬 𝐥𝐨𝐧𝐠𝐞𝐫 𝐭𝐡𝐚𝐧 𝐞𝐧𝐜𝐫𝐲𝐩𝐭𝐢𝐨𝐧: " 
                             + str(decryption_time/(encryption_time - rsa.time_to_generate_keys)) + "x",                             
                             "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str((decryption_time / len(plaintext)) * 1000000), 
                             "\n𝐌𝐢𝐥𝐥𝐢𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " +  str((decryption_time / len(plaintext)) * 1000) 
                            ])
    """

    miscellaneous.testing_general_decrypt_with_key(ciphertext, output_location, plaintext, public_key, private_key,
                                                   char_set_size, encryption_time, "Decryption", "rsa",
                                                   "RSA", "decrypt", encryption_code,
                                                   decryption_code)






# Contains the actual algorithm to decrypt with rsa cipher with private key.
def decrypt(ciphertext, private_key, char_set_size):
    """
    This function decrypts with rsa cipher

    :param ciphertext: (string) the ciphertext to decrypt
    :param private_key: (string) the key to decrypt with. In format "(encoding scheme) d = ..., n = ..."
    :param char_set_size: (integer) the size of the character set that is used
    :return: (string) the deciphered text
    """

    plaintext = "" # Build up the decrypted text here
    plaintext_blocks = [] # List of plaintext blocks
    block_size_bytes = 0 # The size of each rsa block (in bytes)
    d = 0 # The decryption number for decrypting
    n = 0 # The modulus number for encrypting


    # Figure out which char encoding scheme to use(reverse dictionary lookup)
    char_encoding_scheme = [key for key,
                            value in miscellaneous.char_set_to_char_set_size.items() if value == char_set_size][0]

    # Figure out d and n from the private key
    d, n = miscellaneous.read_rsa_key(private_key)


    # Determine the block size in bytes of the ciphertext (should be evenly divisible by 8)
    block_size_bytes = n.bit_length() // 8


    # Figure out the number of characters to read based on the block_size_bytes
    randint = secrets.randbits(block_size_bytes * 8)
    block_size_len = len(miscellaneous.int_to_chars_encoding_scheme_pad(randint, char_encoding_scheme,
                                                                        block_size_bytes * 8))



    # Read in the ciphertext in block_size_bytes. Turn each block into an integer using the correct encoding scheme.
    # Then, use the rsa cipher (on each block) of pow(c, d, n) in order to get the message m (in integer form). Turn
    # the integers into plaintext blocks(through utf-8 interpretation of the bytesarray). Then, concatenate all the
    # blocks
    # together in order to get the full plaintext
    ciphertext_blocks  = []
    while ciphertext != "":
        ciphertext_blocks.append(ciphertext[0: block_size_len])
        ciphertext = ciphertext[block_size_len:]

    # Turn each block into an integer
    ciphertext_blocks = [ miscellaneous.chars_to_int_decoding_scheme(block, char_encoding_scheme)
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



