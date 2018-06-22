import miscellaneous
import time










def execute(data, output_location):
    """
    This function asks the user for more information to conduct the vigenere cipher. Then, it passes this information to
    the specific functions located below(in the format "vig_characterset"). Finally, it returns the encrypted data

    :param data: (string) the data to be encrypted
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
        encrypted = encrypted + encrypted_char

    return encrypted









def vig_unicode(plain_text, key):
    """
    This function encrypts the plain text using the unicode character sets, which has a max value of 1114111. Should
    any of the singular values exceed 1114111, it starts from 0 again. For example, 1114112 would become 0.

    :param plain_text: the text to be encrypted
    :param key: the key with which the encryption is done
    :return: the encrypted text
    """

    encrypted = ""
    key_count = 0
    secondary_key_count = 0
    MAX_CHAR_SET_VAL = 1114112



    for x in plain_text:
        #  figure out the unicode value for each of the characters
        uni_val_plain = ord(x)

        #  figure out the unicode value for the right character in the key, then update for next iteration
        key_char = key[key_count]
        uni_val_key = ord(key_char)

        key_count = (key_count + 1) % len(key)


        #  figure out the character by combining the two unicodes, the add it to the encrypted string
        encrypted_char = chr((uni_val_plain + uni_val_key) % MAX_CHAR_SET_VAL)
        encrypted = encrypted + encrypted_char

    return encrypted






def vig_ascii(plain_text, key):
    """
    This function encrypts the plain text using the ascii character sets, which has a max value of 127. Should
    any of the singular values exceed 127, it starts from 0 again. For example, 128 would become 0.

    :param plain_text: the text to be encrypted
    :param key: the key with which the encryption is done
    :return: the encrypted text
    """

    encrypted = ""
    key_count = 0
    secondary_key_count = 0
    MAX_CHAR_SET_VAL = 128



    for x in plain_text:
        #  figure out the ascii value for each of the characters
        uni_val_plain = ord(x)

        #  figure out the ascii value for the right character in the key, then update for next iteration
        key_char = key[key_count]
        uni_val_key = ord(key_char)

        key_count = (key_count + 1) % len(key)



        #  figure out the character by combining the two ascii's, the add it to the encrypted string
        encrypted_char = chr((uni_val_plain + uni_val_key) % MAX_CHAR_SET_VAL)
        encrypted = encrypted + encrypted_char

    return encrypted










def vig_extended_ascii(plain_text, key):
    """
    This function encrypts the plain text using the extended_ascii character sets, which has a max value of 255. Should
    any of the singular values exceed 255, it starts from 0 again. For example, 256 would become 0.

    :param plain_text: the text to be encrypted
    :param key: the key with which the encryption is done
    :return: the encrypted text
    """

    encrypted = ""
    key_count = 0
    secondary_key_count = 0
    MAX_CHAR_SET_VAL = 256



    for x in plain_text:
        #  figure out the ascii value for each of the characters
        uni_val_plain = ord(x)

        #  figure out the ascii value for the right character in the key, then update for next iteration
        key_char = key[key_count]
        uni_val_key = ord(key_char)

        key_count = (key_count + 1) % len(key)



        #  figure out the character by combining the two ascii's, the add it to the encrypted string
        encrypted_char = chr((uni_val_plain + uni_val_key) % MAX_CHAR_SET_VAL)
        encrypted = encrypted + encrypted_char

    return encrypted