import miscellaneous
import time








def execute(data, output_location):
    """
    This function decrypts data using a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the location to save relevant info into
    :return: (string) the decrypted data
    """


    # Obtain the decrypted text. Also write statistics and relevant info to a file
    decrypted = miscellaneous.symmetric_encrypt_or_decrypt_without_key(data, output_location,
                                                                      "Decryption", "vigenere_nokey", "decrypt")


    # Return encrypted text to be written in cryptography_runner
    return decrypted



# Decrypt in testing mode. So add more statistics about performance. Check for correctness
def testing_execute(ciphertext, output_location, plaintext, key, char_set_size, encryption_time):
    """
    Decrypt and save statistics.

    :param ciphertext: (string) the encrypted text to decipher
    :param output_location: (string) the file to save statistics into
    :param plaintext: (string) the original plaintext
    :param key: (string) the key used to decrypt
    :param char_set_size: (integer) the character set used
    :param encryption_time: (double) the time it took to encrypt using vigenere
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

    miscellaneous.testing_general_decrypt_with_key(ciphertext, output_location, plaintext, key, key, char_set_size,
                                                   encryption_time, "Decryption", "vigenere_nokey",
                                                   "Vigenère without key", "decrypt", encryption_code,
                                                   decryption_code)






# Contains the actual algorithm to decrypt with vigenere cipher without a key TODO
def decrypt(ciphertext):
    """
    This function decrypts a vigenere cipher without a key

    :param ciphertext: (string) the ciphertext to decrypt
    :return: (string) the deciphered text
    """

    plaintext = "" # Build up the decrypted text here
    key_index = 0 # The index of the current char in the key. Iterates from 0 to len() - 1 and repeats.




    return 0








