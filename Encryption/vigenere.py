import miscellaneous
import time










def encrypt(data, output_location):
    """
    This function asks the user for more information to conduct the vigenere cipher. Then, it passes this information to
    the specific functions located below(in the format "vig_characterset"). Finally, it returns the encrypted data

    :param data: the data to be encrypted
    :return: the encrypted data
    """


    vig_type = miscellaneous.take_char_set(miscellaneous.char_sets)




    # TAKE A KEY
    key = input("Enter a key: ")

    # IF THE USER DIDN"T ENTER ANYTHING, SEND AN ERROR MESSAGE AND ASK AGAIN
    while key == "":
        key = input("No key entered! Enter a key: ")




    # START THE TIMER
    start_time = time.time()

    # EXECUTE THE SPECIFIC ENCRYPTION METHOD
    encrypted = eval("vig_" + vig_type + "(data, key)")

    #  END THE TIMER
    elapsed_time = time.time() - start_time

    #  WRITE TO A NEW FILE CONTAINING THE VIGENERE TYPE, KEY, AND SECONDARY KEY, AND TIME ELAPSED, AND TIME PER
    #     CHARACTER
    new_file = open(output_location + "_(Relevant information)", "w", encoding="utf-8")
    new_file.writelines(["The character set is : " + vig_type,
                         "\nThe key is: " + key,
                         "\n Encoded/decoded in: " + str(elapsed_time) + " seconds.",
                         "\n That is " + str((elapsed_time/len(encrypted) * 1000000)) + " microseconds per character."])

    return encrypted
#  END OF DEF ENCRYPT()







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