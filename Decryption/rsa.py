import miscellaneous
import time # For timing to write relevant information into files







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

    # Run the decryption algorithm on the ciphertext
    start_time = time.time()
    decrypted = decrypt(ciphertext, key, char_set_size)
    decryption_time = time.time() - start_time

    # Open file for writing
    new_file = open(output_location, "w", encoding="utf-8")

    # Set up a space for notes
    if decrypted == plaintext:
        new_file.writelines(["RSA\nCORRECT \nNotes: "])
        print("RSA: CORRECT\n")
    else:
        new_file.writelines(["RSA\nINCORRECT \nNotes: "])
        print("RSA: INCORRECT\n")

    # Encryption information
    new_file.writelines(["\n\n\nEncryptionEncryptionEncryptionEncryptionEncryptionEncryptionEncryptionEncryption",
                         "\nThe key is: " + key,
                         "\nEncrypted in: " + str(encryption_time) + " seconds.",
                         "\nThat is " + str(encryption_time / len(decrypted)) + " seconds per character.",
                         "\nThat is " + str((encryption_time / len(decrypted) * 1000000))
                                      + " microseconds per character."])


    # Decryption information
    new_file.writelines(["\n\n\nDecryptionDecryptionDecryptionDecryptionDecryptionDecryptionDecryptionDecryption",
                         "\nThe character set is : " + [char_set for char_set,
                                                        value in miscellaneous.char_set_to_char_set_size.items()
                                                        if value == char_set_size][0],
                         "\nThe key is: " + key,
                         "\nDecrypted in: " + str(decryption_time) + " seconds.",
                         "\nThat is " + str(encryption_time / len(decrypted)) + " seconds per character.",
                         "\nThat is " + str((decryption_time / len(decrypted) * 1000000))
                                      + " microseconds per character."                                         ])



    # Print out the ciphertext
    new_file.writelines(["\n\n\nciphertext: \n" + ciphertext])

    # Print out the decrypted
    new_file.writelines(["\n\n\nDecrypted: \n" + decrypted])

    # Print out the plaintext
    new_file.writelines(["\n\n\nplaintext: \n" + plaintext])

    new_file.close()






# Contains the actual algorithm to decrypt with rsa cipher with private key.
def decrypt(ciphertext, key, char_set_size):
    """
    This function decrypts with rsa cipher

    :param ciphertext: (string) the ciphertext to decrypt
    :param key: (string) the key to decrypt with. In format "(encoding scheme) d = ..., n = ..."
    :param char_set_size: (integer) the size of the character set that is used
    :return: (string) the deciphered text
    """

    # Build up the decrypted text here
    plaintext = ""

    # Figure out which char encoding scheme to use(reverse dictionary lookup)
    char_encoding_scheme = [key for key,
                            value in miscellaneous.char_set_to_char_set_size.items() if value == char_set_size][0]







    return plaintext



