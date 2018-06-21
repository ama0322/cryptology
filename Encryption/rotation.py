import miscellaneous
import time









def encrypt(data, output_location):
    """
    This function asks the user for more information to conduct the vigenere cipher. Then, it passes this information to
    the specific functions located below(in the format "vig_characterset"). Finally, it returns the encrypted data

    :param data: (string) the data to be encrypted
    :param output_location: (string) the location to print out the information
    :return: (string) the encrypted data
    """

    # Obtain the char_set and the endchar
    char_set, num_chars = miscellaneous.take_char_set(miscellaneous.char_sets)

    # Take a key from the user
    key = miscellaneous.get_single_char_key()


    # START THE TIMER
    start_time = time.time()

    # EXECUTE THE ENCRYPTION METHOD
    encrypted = rotation(data, key, num_chars)


    #  END THE TIMER
    elapsed_time = time.time() - start_time

    #  WRITE TO A NEW FILE CONTAINING RELEVANT INFO
    new_file = open(output_location + "_(Relevant information)", "w", encoding="utf-8")
    new_file.writelines(["The character set is : " + char_set,
                         "\nThe key is: " + key,
                         "\n Encoded/decoded in: " + str(elapsed_time) + " seconds.",
                         "\n That is " + str((elapsed_time/len(encrypted) * 1000000)) + " microseconds per character."])

    return encrypted
#  END OF DEF ENCRYPT()


# This function encrypts using our desired configuration and returns the encrypted text.
def rotation(plain_text, key, num_chars):
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







