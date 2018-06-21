import miscellaneous
import time





# Decrypt without a key. Write relevant information and return decrypted text for cryptography_runner
def execute(data, output_location):
    """
    This function decrypts data without a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the file to write relevant information in
    :return: (string) the decrypted data
    """

    # START THE TIMER
    start_time = time.time()

    # EXECUTE THE SPECIFIC DECRYPTION METHOD
    decrypted, char_set = decrypt(data)

    #  END THE TIMER
    elapsed_time = time.time() - start_time

    #  WRITE TO A NEW FILE CONTANING RELEVANT INFO FOR ROTATION_UNKNOWN
    new_file = open(output_location + "_(Relevant information)", "w", encoding="utf-8")
    new_file.writelines(["The character set is : " + char_set,
                         "\nThe key is: " + key,
                         "\nThe percent of words that are English are : " + str(percent_english),
                         "\nEncoded/decoded in: " + str(elapsed_time) + " seconds.",
                         "\nThat is " + str((elapsed_time / len(decrypted) * 1000000)) + " microseconds per character.",
                         "\nThat is " + str((elapsed_time / ord(key) * 1000)) + " milliseconds per rotation."])

    return decrypted






# Actual algorithm to decryption using a rotation cipher without a key
def decrypt(cipher_text):
    """

    :param cipher_text: (string) the cipher text to be decrypted
    :return: (string) the decrypted text
    """

    decrypted = ""

    # Figure out the most likely character set of the cipher_text
    char_set = miscellaneous.char_set_of_cipher_text(cipher_text)
    num_chars = miscellaneous.char_set_to_num_chars.get(char_set)


    # Decrypt the encrypted text using every possible unicode value
    for uni_val_key in range(0, num_chars):

        #  refresh decrypted for this cycle
        decrypted = ""

        #  DECRYPTION PROCESS
        for x in cipher_text:
            #  figure out the unicode value for each of the characters
            uni_val_cipher = ord(x)


            #  figure out the character by combining the two unicodes, the add it to the decrypted string
            decrypted_char = chr((uni_val_cipher - uni_val_key) % num_chars)
            decrypted = decrypted + decrypted_char


        # Check if the decrypted text is in English
        global percent_english
        is_english, percent_english = miscellaneous.isenglish(decrypted)

        # If english, then break and return decrypted. Also, tell what the key is
        if is_english:
            global key
            key = chr(uni_val_key)
            break



        # print updates
        print("Done with: " + chr(uni_val_key))

    return decrypted, char_set



