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
    decrypted = miscellaneous.encrypt_or_decrypt_with_single_char_key(data, output_location,
                                                                      "Decryption", "vigenere", "decrypt")


    # Return encrypted text to be written in cryptography_runner
    return decrypted



# Decrypt in testing mode. So add more statistics about performance. Check for correctness
def testing_execute(cipher_text, output_location, plain_text, key, char_set_size, encryption_time):
    """
    Decrypt and save statistics.

    :param cipher_text: (string) the encrypted text to decipher
    :param output_location: (string) the file to save statistics into
    :param plain_text: (string) the original plain text
    :param key: (string) the key used to decrypt
    :param char_set_size: (integer) the character set used
    :param encryption_time: (double) the time it took to encrypt using vigenere
    :return: None
    """

    # Run the decryption algorithm on the cipher_text
    start_time = time.time()
    decrypted = decrypt(cipher_text, key, char_set_size)
    decryption_time = time.time() - start_time

    # Open file for writing
    new_file = open(output_location, "w", encoding="utf-8")

    # Set up a space for notes
    if decrypted == plain_text:
        new_file.writelines(["Vigenere\nCORRECT \nNotes: "])
    else:
        new_file.writelines(["Vigenere\nINCORRECT \nNotes: "])

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



    # Print out the cipher_text
    new_file.writelines(["\n\n\nCipher text: \n" + cipher_text])

    # Print out the plain_text
    new_file.writelines(["\n\n\nPlain text: \n" + plain_text])

    new_file.close()






# Contains the actual algorithm to decrypt with vigenere cipher with a key
def decrypt(cipher_text, key, char_set_size):
    """
    This function decrypts with vigenere. Instead of adding, subtract

    :param cipher_text: (string) the cipher text to decrypt
    :param key: (string) the key to decrypt with
    :param char_set_size: (integer) the size of the character set that is used
    :return: (string) the deciphered text
    """

    # Build up the decrypted text here
    plain_text = ""

    # The index of the current char in the key. Iterates from 0 to len() - 1 and repeats.
    key_index = 0


    for x in cipher_text:

        #  figure out the unicode value for each of the characters
        uni_val_cipher = ord(x)

        #  figure out the unicode value for the right character in the key, then update for next iteration
        key_char = key[key_index]
        uni_val_key = ord(key_char)
        key_index = (key_index + 1) % len(key)


        #  figure out the character by subtracting the two unicodes, the add it to the decrypted string
        decrypted_char = chr((uni_val_cipher - uni_val_key) % char_set_size)
        plain_text = plain_text + decrypted_char


    return plain_text









def vig_unicode(cipher_text, key):
    """
    This function decrypts the plain text using the unicode character sets, which has a max value of 1114111. Should
    any of the singular values exceed 1114111, it starts from 0 again. For example, 1114112 would become 0.

    :param cipher_text: the text to be decrypted
    :param key: the key with which the decryption is done
    :return: the decrypted text
    """

    decrypted = ""
    key_count = 0
    secondary_key_count = 0
    MAX_CHAR_SET_VAL = 1114112



    for x in cipher_text:
        #  figure out the unicode value for each of the characters
        uni_val_cipher = ord(x)

        #  figure out the unicode value for the right character in the key, then update for next iteration
        key_char = key[key_count]
        uni_val_key = ord(key_char)
        key_count = (key_count + 1) % len(key)



        #  figure out the character by combining the two unicodes, the add it to the decrypted string
        decrypted_char = chr((uni_val_cipher - uni_val_key) % MAX_CHAR_SET_VAL)
        decrypted = decrypted + decrypted_char

    return decrypted






def vig_ascii(cipher_text, key):
    """
    This function decrypts the plain text using the ascii character sets, which has a max value of 127. Should
    any of the singular values exceed 127, it starts from 0 again. For example, 128 would become 0.

    :param cipher_text: the text to be decrypted
    :param key: the key with which the decryption is done
    :return: the decrypted text
    """

    decrypted = ""
    key_count = 0
    secondary_key_count = 0
    MAX_CHAR_SET_VAL = 128



    for x in cipher_text:
        #  figure out the ascii value for each of the characters
        uni_val_cipher = ord(x)

        #  figure out the ascii value for the right character in the key, then update for next iteration
        key_char = key[key_count]
        uni_val_key = ord(key_char)
        key_count = (key_count + 1) % len(key)



        #  figure out the character by combining the two ascii's, the add it to the decrypted string
        decrypted_char = chr((uni_val_cipher - uni_val_key) % MAX_CHAR_SET_VAL)
        decrypted = decrypted + decrypted_char

    return decrypted










def vig_extended_ascii(cipher_text, key):
    """
    This function decrypts the plain text using the extended_ascii character sets, which has a max value of 255. Should
    any of the singular values exceed 255, it starts from 0 again. For example, 256 would become 0.

    :param cipher_text: the text to be decrypted
    :param key: the key with which the decryption is done
    :return: the decrypted text
    """

    decrypted = ""
    key_count = 0
    secondary_key_count = 0
    MAX_CHAR_SET_VAL = 256



    for x in cipher_text:
        #  figure out the ascii value for each of the characters
        uni_val_cipher = ord(x)

        #  figure out the ascii value for the right character in the key, then update for next iteration
        key_char = key[key_count]
        uni_val_key = ord(key_char)
        key_count = (key_count + 1) % len(key)





        #  figure out the character by combining the two ascii's, the add it to the decrypted string
        decrypted_char = chr((uni_val_cipher - uni_val_key) % MAX_CHAR_SET_VAL)
        decrypted = decrypted + decrypted_char

    return decrypted