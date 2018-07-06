import miscellaneous




# Cipher info:
alphabet = miscellaneous.char_sets
key_type = "symmetric"




# Decrypt without a key. Write relevant information and return decrypted text for cryptography_runner
def execute(data, output_location):
    """
    This function decrypts data without a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the file to write relevant information in
    :return: (string) the decrypted data
    """

    # Obtain the decrypted text. Also write statistics and relevant info to a file
    decrypted = miscellaneous.symmetric_ed_without_key(data, output_location,
                                                                      "Decryption", "rotation_nokey", "decrypt")


    # Return encrypted text to be written in cryptography_runner
    return decrypted




# Decrypt in testing form. This means to add some more statistics about performance. Also check for correctness
def testing_execute(ciphertext, output_location, plaintext, key, char_set_size, encryption_time):
    """
    This function executes the deciphering in testing mode. So add more statistics about performance and correctness.

    :param ciphertext: (string) the ciphertext to be decrypted
    :param output_location: (string) the file to write information to
    :param plaintext: (string) the unencrypted plaintext
    :param encryption_time: (integer) the time it took for the plaintext to be encrypted
    :return:
    """
    # Store information from the last encryption done here(Just declarations):

    # Store information from the last decryption done here:
    testing_execute.decrypted_key = ""
    testing_execute.percent_english = 0


    # Encryption code
    encryption_code = \
    r"""new_file.writelines([
                             "\n\n\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                             "\n--------------- key ---------------\n" + public_key +
                             "\n------------------------------------------------------------------------------------" ,
                             "\n𝐓𝐡𝐞 𝐜𝐢𝐩𝐡𝐞𝐫𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + char_set_of_ciphertext(ciphertext),
                             "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(encryption_time) 
                             + " seconds with " + "{:,}".format(len(plaintext)) + " characters.",                             
                             "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str((encryption_time / len(plaintext)) * 1000000)
                            ])
    """

    # Decryption code
    decryption_code = \
    r"""new_file.writelines([
                             "\n\n\n𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                             "\n𝐓𝐡𝐞 𝐩𝐥𝐚𝐢𝐧𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + char_set_of_ciphertext(ciphertext),
                             "\n𝐃𝐞𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(decryption_time) 
                             + " seconds with " + "{:,}".format(len(plaintext)) + " characters.",
                             "\n𝐓𝐢𝐦𝐞𝐬 𝐥𝐨𝐧𝐠𝐞𝐫 𝐭𝐡𝐚𝐧 𝐞𝐧𝐜𝐫𝐲𝐩𝐭𝐢𝐨𝐧: " + str(decryption_time/encryption_time) + "x",                             
                             "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str((decryption_time / len(plaintext)) * 1000000),
                             "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐫𝐨𝐭𝐚𝐭𝐢𝐨𝐧: "  
                             + str(decryption_time / ord(rotation_nokey.testing_execute.decrypted_key) * 1000000),
                             "\n𝐏𝐞𝐫𝐜𝐞𝐧𝐭 𝐨𝐟 𝐭𝐞𝐱𝐭 𝐢𝐧 𝐄𝐧𝐠𝐥𝐢𝐬𝐡: " 
                             + str(rotation_nokey.testing_execute.percent_english * 100)
                            ])
    """


    miscellaneous.testing_general_decrypt_with_key(ciphertext, output_location, plaintext, key, key, char_set_size,
                                                   encryption_time, "Decryption", "rotation_nokey",
                                                   "Rotation without key", "decrypt", encryption_code,
                                                   decryption_code)






# Actual algorithm to decryption using a rotation cipher without a key
def decrypt(ciphertext, key, char_set_size):
    """
    This function attempts to decrypt the ciphertext by running through all the characters in unicode and performing
    a reverse rotation on the ciphertext. The result is checked for English content as confirmation that it is decoded.

    :param ciphertext: (string) the ciphertext to be decrypted
    :param key: (string) NOT USED
    :param char_set_size: (int) NOT USED
    :return: (string) the decrypted text
    :return: (string) the key that was used for encryption
    """

    decrypted = ""
    decrypted_key = "Default"
    percent_english = 0

    # Figure out the most likely character set of the ciphertext
    char_set = miscellaneous.char_set_of_ciphertext(ciphertext)
    char_set_size = miscellaneous.char_set_to_char_set_size.get(char_set)


    # Decrypt the encrypted text using every possible unicode value
    for uni_val_key in range(0, char_set_size):

        #  refresh decrypted for this cycle
        decrypted = ""
        decrypted_list = []

        # Shortened decryption process(First 50,000 letters or less, whichever comes first)
        max = min(49999, len(ciphertext))
        for x in range(0, max):
            decrypted_list.append(chr((ord(ciphertext[x]) - uni_val_key) % char_set_size))
        decrypted = "".join(decrypted_list)
        is_english, percent_english = miscellaneous.is_english_bag_of_words(decrypted)

        # If not english, continue to the next uni_val_key
        if not is_english:

            # print updates
            print("Done with: " + chr(uni_val_key) + "\tPercent English: " + str(percent_english))
            continue


        #  Full DECRYPTION PROCESS
        decrypted = ""
        for x in ciphertext:

            #  figure out the character by combining the two unicodes, the add it to the decrypted string
            decrypted += (chr((ord(x) - uni_val_key) % char_set_size))


        # Check if the decrypted text is in English
        is_english, percent_english = miscellaneous.is_english_bag_of_words(decrypted)


        # print updates
        print("Done with: " + chr(uni_val_key) + "\tPercent English: " + str(percent_english))

        # If english, then break and  return decrypted plus key. Save these values in testing_execute for printing
        if is_english:
            decrypted_key = chr(uni_val_key); testing_execute.decrypted_key = decrypted_key
            testing_execute.percent_english = percent_english
            break

    return decrypted, decrypted_key



