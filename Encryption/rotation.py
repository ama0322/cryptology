import miscellaneous # To handle user input and miscellaneous









# Encrypt using user-entered info. Write relevant information and return encrypted text for cryptography_runner
def execute(data, output_location):
    """
    This function calls the appropriate functions in miscellaneous.py. Those functions will use the encrypt() function
    located below as the algorithm to actually encrypt the text. Then, the cipher text will be returned back to
    cryptography_runner.py

    :param data: (string) the data to be encrypted
    :param output_location: (string) the location to print out the information
    :return: (string) the encrypted data
    """

    # Obtain the encrypted text. Also write statistics and relevant info a file
    encrypted = miscellaneous.encrypt_or_decrypt_with_single_char_key(data, output_location,
                                                                      "Encryption", "rotation", "encrypt")


    # Return encrypted text to be written in cryptography_runner
    return encrypted



# This function contains the actual algorithm to encrypt in a rotation cipher using a key
def encrypt(plain_text, key, char_set_size):
    """
    This function encrypts the plain text using the set of unicode characters from 0 to char_set_size - 1.

    :param plain_text: (string )the text to be encrypted
    :param key: (string) the key with which the encryption is done
    :param char_set_size: (int) The number of characters in the character set
    :return: (string) the encrypted text
    """

    encrypted = "" # the string to build up the encrypted text
    key_index = 0 # the index in the key we are using for the vigenere encrypt


    for x in plain_text:
        #  figure out the unicode value for the current character
        uni_val_plain = ord(x)

        #  figure out the unicode value for the right character in the key
        key_char = key[key_index]
        uni_val_key = ord(key_char)


        #  figure out the character by combining the two ascii's, the add it to the encrypted string
        encrypted_char = chr((uni_val_plain + uni_val_key) % (char_set_size))
        encrypted = encrypted + encrypted_char

        # update key_index for next iteration
        key_index = (key_index + 1) % len(key)

    return encrypted







