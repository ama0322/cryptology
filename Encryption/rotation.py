import miscellaneous
import time









def execute(data, output_location):
    """
    This function asks the user for more information to conduct the cipher. Then it encrypt the information using the
    encrypt function located below. Finally, it returns the encrypted data back to cryptography_runner

    :param data: (string) the data to be encrypted
    :param output_location: (string) the location to print out the information
    :return: (string) the encrypted data
    """

    # Obtain the char_set and the endchar
    char_set, num_chars = miscellaneous.take_char_set(miscellaneous.char_sets)

    # Take a single character key from the user
    key = miscellaneous.get_single_char_key()

    # Execute encryption and write into
    encrypted = miscellaneous.execute_and_write_info(data, key, char_set, output_location,
                                                     "Encryption", "rotation", "encrypt")

    # Return encrypted text to be written in cryptography_runner
    return encrypted



# This function encrypts using our desired configuration and returns the encrypted text.
def encrypt(plain_text, key, num_chars):
    """
    This function encrypts the plain text using the set of unicode characters from 0 to end_char.

    :param plain_text: (string )the text to be encrypted
    :param key: (string) the key with which the encryption is done
    :param num_chars: (int) The number of characters in the character set
    :return: (string) the encrypted text
    """

    encrypted = "" # the string to build up the encrypted text
    key_index = 0 # the index in the key we are using for the vigenere encrypt


    for x in plain_text:
        #  figure out the ascii value for the current character
        uni_val_plain = ord(x)

        #  figure out the ascii value for the right character in the key
        key_char = key[key_index]
        uni_val_key = ord(key_char)


        #  figure out the character by combining the two ascii's, the add it to the encrypted string
        encrypted_char = chr((uni_val_plain + uni_val_key) % (num_chars))
        encrypted = encrypted + encrypted_char

        # update key_index for next iteration
        key_index = (key_index + 1) % len(key)

    return encrypted







