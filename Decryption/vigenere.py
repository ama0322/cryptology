import miscellaneous






# Cipher info:
alphabet = miscellaneous.char_sets
key_type = "symmetric"




# Call the proper functions to decrypt. Return decrypted text back to cryptography_runner.py
def execute(data, output_location):
    """
    This function decrypts data using a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the location to save relevant info into
    :return: (string) the decrypted data
    """


    # Obtain the decrypted text. Also write statistics and relevant info to a file
    decrypted = miscellaneous.symmetric_ed_with_general_key(data, output_location,
                                                                      "Decryption", "vigenere", "decrypt")


    # Return encrypted text to be written in cryptography_runner
    return decrypted



# Decrypt in testing mode. So add more statistics about performance. Check for correctness.
def testing_execute(ciphertext, output_location, plaintext, key, char_set_size, encryption_time):
    """
    Decrypt and save statistics.

    :param ciphertext: (string) the encrypted text to decipher
    :param output_location: (string) the file to save statistics into
    :param plaintext: (string) the original plaintext
    :param key: (string) the key used to decrypt
    :param char_set_size: (int) the character set used
    :param encryption_time: (float) the time it took to encrypt using vigenere
    :return: None
    """

    # Encryption code
    encryption_code = miscellaneous.general_encryption_code

    # Decryption code
    decryption_code = miscellaneous.general_decryption_code

    miscellaneous.testing_general_decrypt_with_key(ciphertext, output_location, plaintext, key, key, char_set_size,
                                                   encryption_time, "Decryption", "vigenere", "Vigenère", "decrypt",
                                                   encryption_code, decryption_code)






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





