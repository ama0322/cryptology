import miscellaneous
import time








def execute(data, output_location):
    """
    This function calls the appropriate functions in miscellaneous.py. Those functions will use the encrypt() function
    located below as the algorithm to actually encrypt the text. Then, the cipher text will be returned back to
    cryptography_runner.py

    :param data: the data to be encrypted
    :return: the encrypted data
    """

    # Obtain the encrypted text. Also write statistics and relevant info a file
    encrypted = miscellaneous.encrypt_or_decrypt_with_general_key(data, output_location,
                                                                      "Encryption", "vigenere_exponential", "encrypt")

    # Return encrypted text to be written in cryptography_runner
    return encrypted






# The actual algorithm to encrypt using a vigenere cipher(exponents instead of addition)
def encrypt(plain_text, key, char_set_size):
    """
    This works the same as regular vigenere, but uses exponents instead of addition. When using unicode_plane0 or
    unicode, adjust to ignore the Surrogates.

    :param data: (string) the data to be encrypted
    :param output_location: (string) the file to write relevant information into
    :return: (string) the encrypted data
    """


    cipher_text = "" # The string used to build up the encrypted text, one character at a time
    key_index = 0 # This indicates the index of the key that the vigenere cipher is currently on


    # Adjust the char set size to exclude surrogates
    if char_set_size > 256:
        char_set_size -= miscellaneous.SURROGATE_BOUND_LENGTH



    # For each character in plain text
    for x in plain_text:

        #  figure out the unicode value for each of the characters
        uni_val_plain = ord(x)

        #  figure out the unicode value for the right character in the key, then update for next iteration
        key_char = key[key_index]
        uni_val_key = ord(key_char)

        key_index = (key_index + 1) % len(key)


        # Figure out the uni_val_cipher. Adjust it to be out of surrogate range
        uni_val_encrypted = (uni_val_plain ** uni_val_key) % char_set_size
        if miscellaneous.SURROGATE_LOWER_BOUND <= uni_val_encrypted:
            uni_val_encrypted = uni_val_encrypted + miscellaneous.SURROGATE_BOUND_LENGTH


        #  figure out the character corresponding to the unicode value, and add to the cipher_text
        encrypted_char = chr(uni_val_encrypted)
        cipher_text = cipher_text + encrypted_char

    return cipher_text









