import miscellaneous
import time









def encrypt(data, output_location):
    """
    This function asks the user for more information to conduct the vigenere cipher. Then, it passes this information to
    the specific functions located below(in the format "vig_characterset"). Finally, it returns the encrypted data

    :param data: the data to be encrypted
    :param output_location: the location to print out the information
    :return: the encrypted data
    """

    # Obtain the char_set and the endchar
    char_set, end_char = miscellaneous.take_char_set(miscellaneous.char_sets)

    # Take a key from the user
    key = get_key()


    # START THE TIMER
    start_time = time.time()

    # EXECUTE THE ENCRYPTION ETHOD
    encrypted = rotation(data, key, end_char)


    #  END THE TIMER
    elapsed_time = time.time() - start_time

    #  WRITE TO A NEW FILE CONTAINING THE VIGENERE TYPE, KEY, AND SECONDARY KEY, AND TIME ELAPSED, AND TIME PER
    #    CHARACTER
    new_file = open(output_location + "_(Relevant information)", "w", encoding="utf-8")
    new_file.writelines(["The character set is : " + char_set,
                         "\nThe key is: " + key,
                         "\n Encoded/decoded in: " + str(elapsed_time) + " seconds.",
                         "\n That is " + str((elapsed_time/len(encrypted) * 1000000)) + " microseconds per character."])

    return encrypted
#  END OF DEF ENCRYPT()


# This function encrypts using our desired configuration and returns the encrypted text.
def rotation(plain_text, key, end_char):
    """
    This function encrypts the plain text using the set of unicode characters from 0 to end_char.

    :param plain_text: the text to be encrypted
    :param key: the key with which the encryption is done
    :param end_char: the end of the unicode set of characters to be encrypted with. For example, for ascii it's 127
    :return: the encrypted text
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
        encrypted_char = chr((uni_val_plain + uni_val_key) % end_char)
        encrypted = encrypted + encrypted_char

        # update key_index for next iteration
        key_index = (key_index + 1) % len(key)

    return encrypted


# This function obtain a key from the user, and returns that
def get_key():

    # TAKE A KEY
    key = input("Enter a key (single character only): ")

    # IF THE USER DID NOT GIVE ANYTHING, SEND AN ERROR MESSAGE AND FORCE THE USER TO ENTER IT AGAN
    while key == "":
        key = input("No key given! Enter a key (single character only): ")

    # IF THE USER DID NOT GIVE A SINGLE CHARACTER, FORCE THE USER TO ENTER IT AGAN
    while not len(key) == 1:
        key = input("Not a single character! Enter a key (single character only): ")

    return key



#OLD FUNCTIONS
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


