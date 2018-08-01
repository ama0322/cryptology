from Cryptography import misc

# Cipher info:
char_set = misc.ALPHABETS
cipher_type = "symmetric"
key_size = "calculated characters (single character)"
ciphertext_alphabet_restricted = True
needs_english = True





########################################################################################## STANDARD FUNCTIONS ##########


# Decrypt without a key. Write relevant information and the decrypted text.
def execute(data:str, output_location:str) -> None:
    """
    This function decrypts data without a key.

    :param data:            (str)      the data to be decrypted
    :param output_location: (str)      the file to write relevant information in
    :return:                (NoneType)
    """

    # Decrypt the ciphertext. Write the plaintext and info to a file
    misc.execute_encryption_or_decryption(data, output_location, "Decryption", "rotation_nokey", "decrypt")




# Figure out the encryption and decryption code. Pass info to misc' testing_execute function
def testing_execute(encryption:str, decryption:str, plaintext:str, plaintext_source:str, encryption_key:str,
                    alphabet_size:int, output_location:str) -> None:
    """
    Conducts a rotation_nokey decryption in testing mode

    :param encryption:       (str)      the name of the encryption cipher to use
    :param decryption:       (str)      the name of the decryption cipher to use (this)
    :param plaintext_source: (str)      the location where the plaintext is found
    :param plaintext:        (str)      the plaintext to encrypt
    :param encryption_key:   (str)      the key to use to encrypt
    :param alphabet_size:    (int)      the size of the character set to use
    :param output_location:  (str)      the name of the file to write statistics in
    :return:                 (NoneType)
    """

    # Store information from the last encryption done here(Just declarations):

    # Store information from the last decryption done here:
    testing_execute.decrypted_key = ""
    testing_execute.percent_english = 0


    # Encryption code
    encryption_code =\
    r"""\
    new_file.writelines([
                        "\n\n\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                        "\n--------------- key ---------------\n" + encryption_key +
                        "\n------------------------------------------------------------------------------------" ,
                        "\n𝐓𝐡𝐞 𝐜𝐢𝐩𝐡𝐞𝐫𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + alphabet_of(ciphertext),
                        "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(encryption_time) 
                            + " seconds with " + "{:,}".format(len(plaintext)) + " characters.",                             
                        "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str((encryption_time / len(plaintext)) * 1000000)
                        ])
    """

    # Decryption code
    decryption_code =\
    r"""\
    new_file.writelines([
                        "\n\n\n𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                        "\n𝐓𝐡𝐞 𝐩𝐥𝐚𝐢𝐧𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + alphabet_of(ciphertext),
                        "\n𝐃𝐞𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(decryption_time) 
                             + " seconds with " + "{:,}".format(len(plaintext)) + " characters.",
                        "\n𝐓𝐢𝐦𝐞𝐬 𝐥𝐨𝐧𝐠𝐞𝐫 𝐭𝐡𝐚𝐧 𝐞𝐧𝐜𝐫𝐲𝐩𝐭𝐢𝐨𝐧: " + str(decryption_time/encryption_time) + "x",                             
                        "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str((decryption_time / len(plaintext)) * 1000000),
                        "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐫𝐨𝐭𝐚𝐭𝐢𝐨𝐧: "  
                             + str(decryption_time / ord(rotation_nokey.testing_execute.decrypted_key)  
                                                     * 1000000),
                        "\n𝐏𝐞𝐫𝐜𝐞𝐧𝐭 𝐨𝐟 𝐭𝐞𝐱𝐭 𝐢𝐧 𝐄𝐧𝐠𝐥𝐢𝐬𝐡: " 
                             + str(rotation_nokey.testing_execute.percent_english * 100)
                        ])
    """


    misc.testing_execute_encryption_and_decryption(encryption, decryption,
                                                            plaintext, plaintext_source, encryption_key, alphabet_size,
                                                            output_location,
                                                            "Rotation without Key",
                                                            encryption_code, decryption_code)






# Returns string, string. This is the actual algorithm to decrypt
def decrypt(ciphertext:str, key:str, alphabet_size:int) -> (str, str):
    """
    This function attempts to decrypt the ciphertext by running through all the characters in unicode and performing
    a reverse rotation on the ciphertext. The result is checked for English content as confirmation that it is decoded.

    :param ciphertext:    (str) the ciphertext to be decrypted
    :param key:           (str) NOT USED
    :param alphabet_size: (int) NOT USED
    :return:              (str) the decrypted text
    :return:              (str) the key that was used for encryption
    """

    decrypted = ""
    decrypted_key = "Default"
    percent_english = 0

    # Figure out the most likely character set of the ciphertext
    alphabet = misc.alphabet_of(ciphertext)
    alphabet_size = misc.CHAR_SET_TO_SIZE.get(alphabet)


    # Decrypt the encrypted text using every possible unicode value
    for uni_val_key in range(0, alphabet_size):

        #  refresh decrypted for this cycle
        decrypted = ""
        decrypted_list = []

        # Shortened decryption process(First 50,000 letters or less, whichever comes first)
        max = min(49999, len(ciphertext))
        for x in range(0, max):
            decrypted_list.append(chr((ord(ciphertext[x]) - uni_val_key) % alphabet_size))
        decrypted = "".join(decrypted_list)
        is_english, percent_english = misc.is_english_bag_of_words(decrypted)

        # If not english, continue to the next uni_val_key
        if not is_english:

            # print updates
            print("Done with: " + chr(uni_val_key) + "\tPercent English: " + str(percent_english))
            continue


        #  Full DECRYPTION PROCESS
        decrypted = ""
        for x in ciphertext:

            #  figure out the character by combining the two unicodes, the add it to the decrypted string
            decrypted += (chr((ord(x) - uni_val_key) % alphabet_size))


        # Check if the decrypted text is in English
        is_english, percent_english = misc.is_english_bag_of_words(decrypted)


        # print updates
        print("Done with: " + chr(uni_val_key) + "\tPercent English: " + str(percent_english))

        # If english, then break and  return decrypted plus key. Save these values in testing_execute for printing
        if is_english:
            decrypted_key = chr(uni_val_key); testing_execute.decrypted_key = decrypted_key
            testing_execute.percent_english = percent_english
            break

    return decrypted, decrypted_key



