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
    decrypted = miscellaneous.symmetric_encrypt_or_decrypt_with_general_key(data, output_location,
                                                                      "Decryption", "vigenere", "decrypt")


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
        new_file.writelines(["Vigenere\nCORRECT \nNotes: "])
        print("Vigenere: CORRECT\n")
    else:
        new_file.writelines(["Vigenere\nINCORRECT \nNotes: "])
        print("Vigenere: INCORRECT\n")

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

    # Print out the plaintext
    new_file.writelines(["\n\n\nplaintext: \n" + plaintext])

    new_file.close()






# Contains the actual algorithm to decrypt with vigenere cipher with a key
def decrypt(ciphertext, key, char_set_size):
    """
    This function decrypts with vigenere. Instead of adding, subtract

    :param ciphertext: (string) the ciphertext to decrypt
    :param key: (string) the key to decrypt with
    :param char_set_size: (integer) the size of the character set that is used
    :return: (string) the deciphered text
    """

    # Build up the decrypted text here
    plaintext = ""

    # The index of the current char in the key. Iterates from 0 to len() - 1 and repeats.
    key_index = 0


    for x in ciphertext:

        #  figure out the unicode value for each of the characters
        uni_val_cipher = ord(x)

        #  figure out the unicode value for the right character in the key, then update for next iteration
        uni_val_key = ord(key[key_index])
        key_index = (key_index + 1) % len(key)


        #  figure out the character by subtracting the two unicodes, the add it to the decrypted string
        decrypted_char = chr(   (uni_val_cipher - uni_val_key) % char_set_size   )
        plaintext += decrypted_char


    return plaintext





