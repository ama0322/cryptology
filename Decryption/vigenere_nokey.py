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
                             "\n\n\nEncryptionEncryptionEncryptionEncryptionEncryptionEncryptionEncryptionEncryption" 
                             + "EncryptionEncryptionEncryptionEncryption",
                             "\nThe ciphertext's character set is: " + char_set_of_ciphertext(ciphertext),
                             "\n\n---------- BEGIN KEY ----------\n" + "(No key given)" +
                             "\n----------- END KEY -----------" ,
                             "\n\nEncrypted " + "{:,}".format(len(plaintext)) + " chars in: " + str(encryption_time) 
                             + " seconds.",                             
                             "\nThat is " + str((encryption_time / len(plaintext) * 1000000)) + " microseconds or " +  
                             str((encryption_time / len(plaintext)) * 1000) + " milliseconds per character."])
    """

    # Decryption code
    decryption_code = \
    r"""new_file.writelines([
                             "\n\n\n\nDecryptionDecryptionDecryptionDecryptionDecryptionDecryptionDecryptionDecryption"
                             + "DecryptionDecryptionDecryptionDecryption",
                             "\nThe plaintext's character set is: " + char_set_of_ciphertext(plaintext),
                             "\n\n---------- BEGIN KEY ----------\n" + private_key +
                             "\n----------- END KEY -----------" ,
                             "\n\nDecrypted " + "{:,}".format(len(plaintext)) + " chars in: " + str(decryption_time) 
                             + " seconds, or " + str(decryption_time/encryption_time) + "x longer then encryption.",                           
                             "\nThat is " + str((decryption_time / len(plaintext) * 1000000)) + " microseconds or " +  
                             str((decryption_time / len(plaintext)) * 1000) + " milliseconds per character."])
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








