import miscellaneous






# Decrypt using user-entered info. Write relevant information and return decrypted text for cryptography_runner
def execute(data, output_location):
    """
    This function decrypts data using a user-provided key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the location to write out relevant info and statistics
    :return: (string) the decrypted data
    """

    # Obtain the decrypted text. Also write statistics and relevant info to a file
    decrypted = miscellaneous.encrypt_or_decrypt_with_single_char_key(data, output_location,
                                                                      "Decryption", "rotation", "decrypt")


    # Return encrypted text to be written in cryptography_runner
    return decrypted









# This function contains the actual algorithm to decrypt a rotation cipher with a key
def decrypt(cipher_text, key, num_chars):
    """
    This function decrypts the cipher_text using the set of unicode characters from 0 to end_char.

    :param plain_text: (string )the text to be encrypted
    :param key: (string) the key with which the encryption is done
    :param num_chars: (int) The number of characters in the character set
    :return: (string) the encrypted text
    """

    encrypted = "" # the string to build up the encrypted text
    key_index = 0 # the index in the key we are using for the vigenere encrypt


    for x in cipher_text:
        #  figure out the unicode value for the current character
        uni_val_cipher = ord(x)

        #  figure out the unicode value for the right character in the key
        key_char = key[key_index]
        uni_val_key = ord(key_char)


        #  figure out the character by subtracting the two ascii's, the add it to the encrypted string
        encrypted_char = chr((uni_val_cipher - uni_val_key) % (num_chars))
        encrypted = encrypted + encrypted_char

        # update key_index for next iteration
        key_index = (key_index + 1) % len(key)

    return encrypted


