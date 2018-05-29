import miscellaneous
import time

char_sets = ["unicode", "ascii", "extended_ascii"] #  unicode has max val of 1114111,
                                 #  ascii has max val of 127


#  Load the text of English_Words.txt as a list
english_words = set(line.strip() for line in open("Library/English_Words.txt"))




def decrypt(data, output_location):
    """
    This function decrypts data without a key

    :param data: the data to be decrypted
    :return: the decrypted data
    """


    #  FIGURE OUT THE CHARACTER SET THAT THE USER WANTS TO USE
    vig_type = miscellaneous.take_char_set(char_sets)



    # START THE TIMER
    start_time = time.time()


    # EXECUTE THE SPECIFIC DECRYPTION METHOD
    decrypted = eval("vig_" + vig_type + "(data)")

    #  END THE TIMER
    elapsed_time = time.time() - start_time

    #  WRITE TO A NEW FILE CONTAINING THE VIGENERE TYPE, KEY, AND SECONDARY KEY, AND TIME ELAPSED, AND TIME PER
    #     CHARACTER
    new_file = open(output_location + "_(Relevant information)", "w", encoding="utf-8")
    new_file.writelines(["The character set is : " + vig_type,
                         "\nThe key is: " + key,
                         "\nThe percent of words that are English are : " + str(percent_english),
                         "\nEncoded/decoded in: " + str(elapsed_time) + " seconds.",
                         "\nThat is " + str((elapsed_time/len(decrypted) * 1000000)) + " microseconds per character."])

    return decrypted
#  END OF DEF DECRYPT()




def vig_unicode(cipher_text):
    """
    This function decrypts the plain text using the unicode character sets, which has a max value of 1114111. Should
    any of the singular values exceed 1114111, it starts from 0 again. For example, 1114112 would become 0. Because the
    key is unknown, I try all unicode values as a possible key. Once I have done that, I will look at the words in
    the result, and I will see if it is deciphered. If it is deciphered, almost every single word will be found in the
    english_words list that I have imported.

    :param cipher_text: the text to be decrypted
    :return: the decrypted text
    """

    decrypted = ""
    key_count = 0
    secondary_key_count = 0
    MAX_CHAR_SET_VAL = 1114112
    PERCENT_ENGLISH_THRESHOLD = 0.15



    # Decrypt the encrypted text using every possible unicode value
    for uni_val_key in range(0, MAX_CHAR_SET_VAL):

        #  refresh decrypted for this cycle
        decrypted = ""

        #  DECRYPTION PROCESS
        for x in cipher_text:
            #  figure out the unicode value for each of the characters
            uni_val_cipher = ord(x)


            #  figure out the character by combining the two unicodes, the add it to the decrypted string
            decrypted_char = chr((uni_val_cipher - uni_val_key) % MAX_CHAR_SET_VAL)
            decrypted = decrypted + decrypted_char


        total_words = len(decrypted.split())
        english_word_counter = 0

        for word in decrypted.split():
            if word in english_words:
                english_word_counter = english_word_counter + 1

        #  check if there is moslty english words. If so, break and return decrypted. also tell what the key is
        if english_word_counter / total_words >= PERCENT_ENGLISH_THRESHOLD:
            global key
            key = chr(uni_val_key)

            global percent_english
            percent_english = english_word_counter / total_words
            break


        # print updates
        print("Done with: " + chr(uni_val_key))

    return decrypted


#  END OF DEF_VIG_UNICODE