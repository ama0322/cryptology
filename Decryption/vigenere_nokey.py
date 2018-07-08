import miscellaneous

# Cipher info:
alphabet = miscellaneous.char_sets
cipher_type = "symmetric"
key_size = "calculated characters (multiple characters) "









def execute(data, output_location):
    """
    This function decrypts data using a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the location to save relevant info into
    :return: (string) the decrypted data
    """


    # Encrypt the plaintext. Print out the ciphertext and relevant information
    miscellaneous.execute_encryption_or_decryption(data, output_location,
                                                   "Decryption", "vigenere_nokey", "decrypt")




# Figure out the encryption and decryption code. Pass info to miscellaneous' testing_execute function
def testing_execute(encryption, decryption, plaintext, encryption_key, char_set_size, output_location):
    """
    Conducts a rotation decryption in testing mode

    :param encryption: (string) the name of the encryption cipher to use
    :param decryption: (string) the name of the decryption cipher to use (this)
    :param plaintext: (string) the plaintext to encrypt
    :param encryption_key: (string) the key to use to encrypt
    :param char_set_size: (int) the size of the character set to use
    :param output_location: (string) the name of the file to write statistics in
    :return: None
    """

    # Encryption code
    encryption_code = \
        r"""new_file.writelines([
                                 "\n\n\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                                 "\n--------------- key ---------------\n" + public_key +
                                 "\n------------------------------------------------------------------------------------" ,
                                 "\n𝐓𝐡𝐞 𝐜𝐢𝐩𝐡𝐞𝐫𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + 
                                 char_set_of_ciphertext(ciphertext),
                                 "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(encryption_time) 
                                 + " seconds with " + "{:,}".format(len(plaintext)) + " characters.",                 
                                 "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str((encryption_time / len(plaintext)) * 1000000), 
                                 "\n𝐌𝐢𝐥𝐥𝐢𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " +  str((encryption_time / len(plaintext)) * 1000) 
                                ])
        """

    # Decryption code
    decryption_code = \
    r"""new_file.writelines([
                             "\n\n\n𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                             "\n𝐓𝐡𝐞 𝐩𝐥𝐚𝐢𝐧𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + char_set_of_ciphertext(ciphertext),
                             "\n𝐃𝐞𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(decryption_time) 
                             + " seconds with " + "{:,}".format(len(plaintext)) + " characters.",
                             "\n𝐓𝐢𝐦𝐞𝐬 𝐥𝐨𝐧𝐠𝐞𝐫 𝐭𝐡𝐚𝐧 𝐞𝐧𝐜𝐫𝐲𝐩𝐭𝐢𝐨𝐧: " + str(decryption_time/encryption_time) + "x",                             
                             "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str((decryption_time / len(plaintext)) * 1000000), 
                             "\n𝐌𝐢𝐥𝐥𝐢𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " +  str((decryption_time / len(plaintext)) * 1000) 
                            ])
    """

    miscellaneous.testing_execute_encryption_and_decryption(encryption, decryption,
                                                            plaintext, encryption_key, char_set_size,
                                                            output_location,
                                                            "Vigenère without a Given Key",
                                                            encryption_code, decryption_code)






# Returns string, string. This is the actual algorithm to decrypt TODO
def decrypt(ciphertext):
    """
    This function decrypts a vigenere cipher without a key

    :param ciphertext: (string) the ciphertext to decrypt
    :return: (string) the deciphered text
    """

    plaintext = "" # Build up the decrypted text here
    key_index = 0 # The index of the current char in the key. Iterates from 0 to len() - 1 and repeats.


    pass










