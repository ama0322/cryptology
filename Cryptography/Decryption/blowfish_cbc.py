from Cryptography.Decryption import blowfish                            # Access to basic blowfish functions
from Cryptography import misc



import copy    # Used to deepcopy



# Cipher info:
char_set = misc.BINARY_TO_CHAR_ENCODING_SCHEMES
cipher_type = "symmetric"
key_size = "multiple generated characters"           # encrypt() generates its own key



# Cipher settings:
key_bits = blowfish.key_bits                         # 32-448 bits long




########################################################################################## STANDARD FUNCTIONS ##########

# Decrypt using user-entered info. Write relevant information and the decrypted text
def execute(data:str, output_location:str) -> None:
    """
    This function decrypts data using a user-provided key.

    :param data:            (str) the data to be decrypted
    :param output_location: (str) the location to write out relevant info and statistics
    :return:                None
    """


    # Decrypt the ciphertext. Write the plaintext and info to a file
    misc.execute_encryption_or_decryption(data, output_location, "Decryption", "blowfish_cbc", "decrypt")




# Figure out the encryption and decryption code. Pass info to misc' testing_execute function
def testing_execute(encryption:str, decryption:str, plaintext:str, plaintext_source:str, encryption_key:str,
                    encoding:int, output_location:str) -> None:
    """
    Conducts a rotation decryption in testing mode

    :param encryption: (string) the name of the encryption cipher to use
    :param decryption: (string) the name of the decryption cipher to use (this)
    :param plaintext_source: (string) the location where the plaintext is found
    :param plaintext: (string) the plaintext to encrypt
    :param encryption_key: (string) the key to use to encrypt
    :param encoding: (int) the size of the character set to use
    :param output_location: (string) the name of the file to write statistics in
    :return: None
    """

    # Store statistics from the last encryption here (Just declarations):
    testing_execute.time_for_key_schedule = 0
    testing_execute.num_blocks = 0
    testing_execute.block_size = 0



    # Encryption code
    encryption_code = \
		r"""new_file.writelines([
                                 "\n\n\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                                 "\n--------------- key " 
                                    + str(blowfish_cbc.key_bits) + "-bit ---------------\n" 
                                    + generated_key 
                                    + "\n-----------------------------------------------"
                                    + "-------------------------------------" ,
                                 "\nTime to conduct key schedule: " 
                                    + str(blowfish_cbc.testing_execute.time_for_key_schedule) + "(s)",
                                 "\n𝐓𝐡𝐞 cipher𝐭𝐞𝐱𝐭'𝐬 encoding scheme 𝐢𝐬: " + char_encoding_scheme_of(ciphertext),
                                 "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧 these seconds: " 
                                    + str(encryption_time - blowfish_cbc.testing_execute.time_for_key_schedule) 
                                    + " (s)" 
                                    + " with " + "{:,}".format(len(plaintext)) + " characters and " 
                                    + "{:,}".format(blowfish_cbc.testing_execute.num_blocks) 
                                    + " blocks (" + str(blowfish_cbc.testing_execute.block_size) 
                                    + " characters each)",                       
                                 "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str((encryption_time / len(plaintext)) * 1000000)
                                    + " (μs)"
                                ])
        """

    # Decryption Code
    decryption_code = \
		r"""new_file.writelines([
                                 "\n\n\n𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                                 "\n𝐓𝐡𝐞 𝐩𝐥𝐚𝐢𝐧𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + alphabet_of(plaintext),
                                 "\n𝐃𝐞𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧 these seconds: " + str(decryption_time) + " (s)"
                                    + " with " + "{:,}".format(len(plaintext)) + " characters and " 
                                    + "{:,}".format(blowfish_cbc.testing_execute.num_blocks) 
                                    + " blocks (" + str(blowfish_cbc.testing_execute.block_size) 
                                    + " characters each)",  
                                 "\n𝐓𝐢𝐦𝐞𝐬 𝐥𝐨𝐧𝐠𝐞𝐫 𝐭𝐡𝐚𝐧 𝐞𝐧𝐜𝐫𝐲𝐩𝐭𝐢𝐨𝐧: " 
                                    + str(decryption_time/(encryption_time 
                                                                - blowfish_cbc.testing_execute.time_for_key_schedule))  
                                    + " (times)",                                     
                                 "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str((decryption_time / len(plaintext)) * 1000000)
                                    + " (μs)"
                                ])
        """

    misc.testing_execute_encryption_and_decryption(encryption, decryption,
                                                            plaintext, plaintext_source, encryption_key, encoding,
                                                            output_location,
                                                            "Blowfish with Cipher Block Chaining",
                                                            encryption_code, decryption_code)






# This is the actual algorithm to decrypt
def decrypt(ciphertext:str, key:str, encoding:str) -> str:
    """
    This function decrypts using blowfish cipher. Process is almost exactly the same, but the p_array is used in reverse
    order

    :param ciphertext: (str) the text to be encrypted
    :param key:        (str) the key with which the encryption is done
    :param encoding:   (str) Name of the binary-to-char encoding scheme
    :return:           (str) the encrypted text
    """


    ciphertext        = ciphertext          # The ciphertext to decrypt
    ciphertext_blocks = []                  # Store ciphertext_blocks here
    plaintext_blocks  = []                  # Store plaintext_blocks here
    plaintext         = ""                  # Create plaintext here



    # Divide the ciphertext into 64-bit int blocks.
    sample_64_bits = misc.int_to_chars_encoding_scheme(0xFFFFFFFF00000000, encoding)  # Turn 64 bits to chars w/ encode
    chars_in_bloc = len(sample_64_bits)                                               # Save how many chars to read
    original_ciphertext_len = len(ciphertext)
    while ciphertext != "":                                                           # Read ciphertext until done
        ciphertext_blocks.append(ciphertext[0 : chars_in_bloc])                       # Save block
        ciphertext = ciphertext[ chars_in_bloc : ]                                    # Cut out what was just read
        print("To decryption blocks: "
			  + str((len(ciphertext_blocks) * chars_in_bloc
					 / original_ciphertext_len) * 100)
			  + "%")
    ciphertext_blocks = [misc.chars_to_int_decoding_scheme(block, encoding)           # Turn chars to int
                         for block in ciphertext_blocks]





    # Conduct the key schedule. Exactly the same as was done in Encryption
    p_array_schedule = copy.deepcopy(blowfish.p_array)                      # Get original p_array
    s_boxes_schedule = copy.deepcopy(blowfish.s_boxes)                      # Get original s boxes
    iv, key = _read_blowfish_cbc_key(key, encoding)                         # Get regular key and iv
    key, p_array_schedule, s_boxes_schedule = blowfish.run_key_schedule(key, p_array_schedule, s_boxes_schedule)





    # Blowfish decrypt the text (on each 64-bit block)
    p_array_schedule.reverse()                                                          # Reverse p_array for decryption
    for i in range(0, len(ciphertext_blocks)):
        plaintext_blocks.append(blowfish.blowfish_on_64_bits(ciphertext_blocks[i],      # Decrypt
                                p_array_schedule, s_boxes_schedule))
        print("Decrypting: " + str((i / len(ciphertext_blocks)) * 100)                  # Print updates
              	+ "%")
    # Reverse the cbc on the blocks
    plaintext_blocks[0] = iv ^ plaintext_blocks[0]                                      # XOR first bloc with iv
    for i in range(1, len(plaintext_blocks)):                                           # XOR other blocs with prev one
        plaintext_blocks[i] = plaintext_blocks[i] ^ plaintext_blocks[i - 1]






    # Convert the decrypted int blocks into utf-8 text
    plaintext_blocks = [hex(block)[2:]                          # Convert int blocks to hex blocks (remove lead "0x")
                        for block in plaintext_blocks]
    for i in range(1, len(plaintext_blocks)):                   # Pad with 0's up to 16 digits (except 1st, the 0 index)
        plaintext_blocks[i] = (16 - len(plaintext_blocks[i])) \
                               * "0" + plaintext_blocks[i]
    for block in plaintext_blocks:                              # Concatenate all the blocks
        plaintext += block
    plaintext = bytearray.fromhex(plaintext).decode("utf-8")    # Read hex as utf-8



    return plaintext





######################################################################################### ANCILLARY FUNCTIONS ##########



# Reads cbc key for the IV and the original blowfish key
def _read_blowfish_cbc_key(key:str, encoding:str) -> (int, int):
    """
    Function to read the cbc key to get the IV and original blowfish key.

    :param key:      (str) the cbc key to read
    :param encoding: (str) the name of the encoding scheme to use
    :return:         (int) the initialization vector
    :return:         (int) the regular blowfish key
    """



    # The IV is 64-bits. Check how many characters that is in the chosen encoding scheme
    sixty_four_bits = 0xFFFFFFFF00000000                                  # 16 random hex digits (64 bits)
    iv_chars_to_read = len(misc.int_to_chars_encoding_scheme_pad(         # Find length of 64 bits char encoded
                                         sixty_four_bits, encoding, 64))



    # Read the iv portion of the cbc_key. Turn that into an int
    iv = key[0: iv_chars_to_read]
    iv = misc.chars_to_int_decoding_scheme(iv, encoding)


    # Read the blowfish key portion of the cbc key. Turn that into an int
    blowfish_key = key[iv_chars_to_read: ]
    blowfish_key = misc.chars_to_int_decoding_scheme(blowfish_key, encoding)


    # Return
    return iv, blowfish_key









