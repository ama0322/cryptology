import miscellaneous
import time










def execute(data, output_location):
    """
    This function calls the appropriate functions in miscellaneous.py. Those functions will use the encrypt() function
    located below as the algorithm to actually encrypt the text. Then, the cipher text will be returned back to
    cryptography_runner.py

    :param data: (string) the data to be encrypted
    :param output_location: (string) the file to write relevant information into
    :return: (string) the encrypted data
    """


    # Obtain the encrypted text. Also write statistics and relevant info a file
    encrypted = miscellaneous.encrypt_or_decrypt_with_general_key(data, output_location,
                                                                      "Encryption", "vigenere", "encrypt")

    # Return encrypted text to be written in cryptography_runner
    return encrypted





# The actual algorithm to encrypt using a vigenere cipher
def encrypt(plain_text, key, char_set_size):
    """
    This function encrypts with a straight vigenere cipher. This uses the set of unicode values from 0 to
    char_set_size - 1.

    :param plain_text: (string) the plain text to encrypt with
    :param key: (string) the string to encrypt with
    :param char_set_size: (integer) the number of characters in the character set used
    :return: (string) the encrypted text
    """

    cipher_text = "" # The string used to build up the encrypted text, one character at a time
    key_index = 0 # This indicates the index of the key that the vigenere cipher is currently on


    # For each character in plain text
    for x in plain_text:

        #  figure out the unicode value for each of the characters
        uni_val_plain = ord(x)

        #  figure out the unicode value for the right character in the key, then update for next iteration
        key_char = key[key_index]
        uni_val_key = ord(key_char)

        key_index = (key_index + 1) % len(key)


        #  figure out the character by combining the two unicodes, the add it to the encrypted string
        encrypted_char = chr((uni_val_plain + uni_val_key) % char_set_size)
        cipher_text = cipher_text + encrypted_char

    return cipher_text









