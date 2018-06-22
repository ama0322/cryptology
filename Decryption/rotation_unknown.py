import miscellaneous
import time # To time decryption. This information will be written to a file





# Decrypt without a key. Write relevant information and return decrypted text for cryptography_runner
def execute(data, output_location):
    """
    This function decrypts data without a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the file to write relevant information in
    :return: (string) the decrypted data
    """

    # Obtain the decrypted text. Also write statistics and relevant info to a file
    decrypted = miscellaneous.encrypt_or_decrypt_without_key(data, output_location,
                                                                      "Decryption", "rotation_unknown", "decrypt")


    # Return encrypted text to be written in cryptography_runner
    return decrypted




# Decrypt in testing form. This means to add some more statistics about performance. Also check for correctness
def testing_execute(cipher_text, output_location, plain_text, encryption_time):
    """
    This function executes the deciphering in testing mode. So add more statistics about performance and correctness.

    :param cipher_text: (string) the cipher text to be decrypted
    :param output_location: (string) the file to write information to
    :param plain_text: (string) the unencrypted plain text
    :param encryption_time: (integer) the time it took for the plain text to be encrypted
    :return:
    """


    # Run the decryption algorith on the cipher_text
    start_time = time.time()
    decrypted, char_set, key = decrypt(cipher_text)
    decryption_time = time.time() - start_time

    # Open file for writing
    new_file = open(output_location, "w", encoding="utf-8")

    # Set up a space for notes
    if decrypted == plain_text:
        new_file.writelines(["CORRECT \nNotes: "])
    else:
        new_file.writelines(["INCORRECT \nNotes: "])

    # Encryption information
    new_file.writelines(["\n\n\nEncryptionEncryptionEncryptionEncryptionEncryptionEncryptionEncryptionEncryption",
                         "\nThe key is: " + key,
                         "\nEncrypted in: " + str(encryption_time) + " seconds.",
                         "\nThat is " + str(encryption_time / len(decrypted)) + " seconds per character.",
                         "\nThat is " + str((encryption_time / len(decrypted) * 1000000))
                                      + " microseconds per character."])


    # Decryption information
    new_file.writelines(["\n\n\nDecryptionDecryptionDecryptionDecryptionDecryptionDecryptionDecryptionDecryption",
                         "\nThe character set is : " + char_set,
                         "\nThe key is: " + key,
                         "\nThe percent of words that are English are : " + str(percent_english),
                         "\nDecrypted in: " + str(decryption_time) + " seconds.",
                         "\nThat is " + str(encryption_time / len(decrypted)) + " seconds per character.",
                         "\nThat is " + str((decryption_time / len(decrypted) * 1000000))
                                      + " microseconds per character.",
                         "\nThat is " + str((decryption_time / (ord(key) + 1) * 1000)) + " milliseconds per rotation."])
    new_file.close()






# Actual algorithm to decryption using a rotation cipher without a key
def decrypt(cipher_text):
    """
    This function attempts to decrypt the cipher text by running through all the characters in unicode and performing
    a reverse rotation on the cipher_text. The result is checked for English content as confirmation that it is decoded.

    :param cipher_text: (string) the cipher text to be decrypted
    :return: (string) the decrypted text
    :return: (string) the character set that was used for encryption
    :return: (string) the key that was used for encryption
    """

    decrypted = ""

    # Figure out the most likely character set of the cipher_text
    char_set = miscellaneous.char_set_of_cipher_text(cipher_text)
    char_set_size = miscellaneous.char_set_to_char_set_size.get(char_set)


    # Decrypt the encrypted text using every possible unicode value
    for uni_val_key in range(0, char_set_size):

        #  refresh decrypted for this cycle
        decrypted = ""


        # Shortened decryption process(First 10,000 letters or less, whichever comes first)
        max = min(9999, len(cipher_text))
        for x in range(0, max):
            decrypted += (chr((ord(cipher_text[x]) - uni_val_key) % char_set_size))
        global percent_english
        is_english, percent_english = miscellaneous.is_english_bag_of_words(decrypted)

        # If not english, continue to the next uni_val_key
        if not is_english:

            # print updates
            print("Done with: " + chr(uni_val_key) + "\tPercent English: " + str(percent_english))
            continue


        #  Full DECRYPTION PROCESS
        decrypted = ""
        for x in cipher_text:

            #  figure out the character by combining the two unicodes, the add it to the decrypted string
            decrypted += (chr((ord(x) - uni_val_key) % char_set_size))



        # Check if the decrypted text is in English
        is_english, percent_english = miscellaneous.is_english_bag_of_words(decrypted)

        # If english, then break and return decrypted. Also, tell what the key is
        if is_english:
            key = chr(uni_val_key)
            break



        # print updates
        print("Done with: " + chr(uni_val_key))

    return decrypted, char_set, key



