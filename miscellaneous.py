import time # for timing the encryption/decryption processes
import csv # to convert ngram csv to a dictionary
import string # to remove punctuation from a string

char_sets = ["unicode", "ascii", "extended_ascii"] #  unicode has max val of 1114111,
                                                   #  ascii has max val of 127
                                                   #  extended_ascii has max val of 255

# Dictionery with character sets to the number of characters in them
char_set_to_char_set_size = {
    "ascii": 128,
    "extended_ascii": 256,
    "unicode": 1114112
}

# Dictionary with decryption methods to their corresponding encryption method
decryption_corresponding_encryption = {
    "rotation": "rotation",
    "rotation_unknown": "rotation",
    "vigenere": "vigenere",
    "vigenere_multiplicative": "vigenere_exponential",
    "vigenere_exponential": "vigenere_exponential"
}


# Dictionary with encryption methods to the type of key used (2 represents a general key of any positive size)
encryption_key_type = {
    "rotation": 1,
    "vigenere": 2,
    "vigenere_exponential": 2,
    "vigenere_exponential": 2
}


# Dictionary with decryption methods to whether or not they need keys
does_decryption_need_key = {
    "rotation": True,
    "rotation_unknown": False,
    "vigenere": True,
    "vigenere_exponential": True,
    "vigenere_multiplicative": True
}


#  The set contaning english word. Load into this if necessary
english_words = None

# The dictionary containing mappings from ngram to its count. Load into this if necessary
ngram_dict = None

######################################################################### USER INTERFACING AND FUNCTION CALLS ##########



# This function runs encryption/decryption on a single char key. It asks for user info and runs everything
def encrypt_or_decrypt_with_single_char_key(data, output_location, package, module, encrypt_or_decrypt):
    """
    This function runs encryption/decryption on a single character key. It obtains information from the user necessary
    to run the encryption/decryption in a particular configuration(such as with character set) and writes statistics
    and relevant information to a file.

    :param data: (string) the data to be encrypted/decrypted
    :param output_location: (string) the file to write stats and relevant info to
    :param package: (string) the package in which the encryption/decryption function is in
    :param module: (string) the module in which the encryption/decryption function is in
    :param encrypt_or_decrypt: (string) specifies encryption or decryption
    :return: (string) the encrypted text
    """

    # Obtain the char_set and the endchar
    char_set, num_chars = _take_char_set(char_sets)

    # Take a single character key from the user
    key = _get_single_char_key()

    # Execute encryption and write into
    text = _execute_and_write_info(data, key, char_set, output_location,
                                                     package, module, encrypt_or_decrypt)

    # Return encrypted text to be written in cryptography_runner
    return text



# This function runs encryption/decryption on a key of any size. It asks for user info and runs everything
def encrypt_or_decrypt_with_general_key(data, output_location, package, module, encrypt_or_decrypt):
    """
    This function runs encryption/decryption on a general key. It obtains information from the user necessary
    to run the encryption/decryption in a particular configuration (such as with character set) and writes statistics
    and relevant information to a file.

    :param data: (string) the data to be encrypted/decrypted
    :param output_location: (string) the file to write stats and relevant info to
    :param package: (string) the package in which the encryption/decryption function is in
    :param module: (string) the module in which the encryption/decryption function is in
    :param encrypt_or_decrypt: (string) specifies encryption or decryption
    :return: (string) the encrypted text
    """

    # Obtain the char_set and the end_char
    char_set, num_chars = _take_char_set(char_sets)

    # Take a single character key from the user
    key = _get_general_key()

    # Execute encryption and write into
    text = _execute_and_write_info(data, key, char_set, output_location,
                                                     package, module, encrypt_or_decrypt)

    # Return encrypted text to be written in cryptography_runner
    return text


# This function runs decryption without a key.
def encrypt_or_decrypt_without_key(data, output_location, package, module, encrypt_or_decrypt):

    # Execute the decryption and write into
    decrypted = _execute_and_write_info_no_key(data, output_location, package, module, encrypt_or_decrypt)

    # Return decrypted text to be written in cryptography_runner
    return decrypted



########################################################################################### USEFUL ALGORITHMS ##########

# This function figures out what character set the encrypted data is in. NOT 100% accurate
def char_set_of_cipher_text(cipher_text):
    """
    This fucntion iterates through all the characters in the cipher text and checks what sort of character set they are
    in. Note that this does not 100% guarantee that the plain_text was encrypted using this particular character
    set. More accurate for longer cipher_texts.

    :param cipher_text: (string) the cipher text
    :return: (string) the character set the cipher_text was most likely encrypted in
    """

    # first pass through cipher_text, check if there are unicode characters (256 and above)
    for x in cipher_text:
        if ord(x) >= 256:
            return "unicode"

    # second pass through cipher_text, check if there are extended_ascii characters(128 and above)
    for x in cipher_text:
        if ord(x) >= 128:
            return "extended_ascii"

    # Otherwise, only ascii characters
        return "ascii"


# This function figures out whether the data is in English. Adjust threshold as necessary. Also return percent english
def is_english_bag_of_words(data):
    """
    This function checks a string of data for English words. If it is mostly in English, the decryption has probably
    succeeded. This function uses the bag of words approach, in which the given data is separated into words, and
    the words are checked against a set of english words.

    :param data: (string) Check this for English
    :return: (boolean) indicates whether or not the text is in english
    :return: (double) the percentage of words that are in english
    """

    # Remove punctuation from the data
    data = data.replace(", " , " ")
    data = data.replace(". ", " ")
    data = data.replace("; ", " ")
    data = data.replace("? ", " ")
    data = data.replace("! ", " ")
    data = data.replace("-", " ")
    data = data.replace("\"", "")
    data = data.replace("'s ", " ")

    # Load the dictionary of english words into english_words (if necessary)
    global english_words
    if english_words is None:
        english_words = set(line.strip() for line in open("Library/English_Words.txt"))


    # Percent of text that is english needed to pass as plaintext
    percent_english_threshold = 0.15

    words = data.split()
    total_words = len(words)
    english_word_counter = 0



    for word in words:
        if word.lower() in (english_words):
            english_word_counter = english_word_counter + 1

    #  If it passes the percent english threshold, return true and the percent english
    if (english_word_counter / total_words) >= percent_english_threshold:
        return True, (english_word_counter / total_words)


    # Else, return False and also the percent english
    return False, (english_word_counter / total_words)



# This function figures out whether data is in English. TODO
def is_english_n_grams(data, ngram_length):
    """
    This checks a string of data for ngrams, where the grams are letters. If these ngrams match the ngrams expected
    in English, it is probably in english. Possible ngram values are 1-9 (recommended: 2)

    :param data: (string) Check this for english
    :return: (boolean) whether or not the data is in english
    """


    # Load into ngram_dict if it is None or has different ngram length
    global ngram_dict
    if ngram_dict is None or len(next(iter(ngram_dict))) != ngram_length:
        with open(eval("Library/ngrams" + ngram_length + ".txt"), newline='') as my_file:
            reader = csv.reader(my_file)
            ngram_dict = dict(reader)  # Read each row as key-value pair


############################################################################################ HELPER FUNCTIONS ##########

#  This helper function asks the user for a character set. It will only accept character sets that are available.
def _take_char_set(char_sets):
    """
    This functions asks the user to input a selection(a char set). THis selection is compared against char_sets
    in order to make sure that it is a valid selection

    :param char_sets: (list) the list of all character sets
    :return: (string) the user-entered character set
    :return: (integer) the number of characters in the selected character set
    """


    previous_entry_invalid = False
    #  TAKE AN INPUT FOR THE CHARACTER SET
    while True:

        #  Print out the prompt for the user. If the previous entry was invalid, say so
        if not previous_entry_invalid:
            selection = input("Enter the character set to be used: ")
        else:
            selection = input("Character set invalid! Enter a new character set: ")
            previous_entry_invalid = False

        # Print out the available character sets, then continue
        if selection[0:4] == "info":
            print("The available character sets are: ")
            for x in range(0, len(char_sets)):
                print("                                  " + char_sets[x])
            continue

        # Test that the user entry is a valid character set. If so, exit out of the forever loop
        for x in range(0, len(char_sets)):
            broken = False
            if selection.rstrip() == char_sets[x]:
                broken = True
                break
        if broken:
            break

        # If here, that means the entry was invalid. Loop again
        previous_entry_invalid = True
    # END OF FOREVER LOOP TO TAKE A CHARACTER SET



    # figure out the end_char of the character set
    end_char = char_set_to_char_set_size.get(selection)

    return selection, end_char



# This helper function obtain a single char key from the user and returns that
def _get_single_char_key():
    """
    This function obtains a key from the user that must be a single character

    :return: (string) the single character key
    """

    # TAKE A KEY
    key = input("Enter a key (single character only): ")

    # IF THE USER DID NOT GIVE ANYTHING, SEND AN ERROR MESSAGE AND FORCE THE USER TO ENTER IT AGAN
    while key == "":
        key = input("No key given! Enter a key (single character only): ")

    # IF THE USER DID NOT GIVE A SINGLE CHARACTER, FORCE THE USER TO ENTER IT AGAN
    while not len(key) == 1:
        key = input("Not a single character! Enter a key (single character only): ")

    return key



# This help function obtains a general key from the user and returns that
def _get_general_key():
    """
    This function obtains a key of any length fro the user

    :return: (string) the user-entered key
    """

    # TAKE A KEY
    key = input("Enter a key: ")

    # IF THE USER DID NOT GIVE ANYTHING, SEND AN ERROR MESSAGE AND FORCE THE USER TO ENTER IT AGAN
    while key == "":
        key = input("No key given! Enter a key (single character only): ")

    return key



# This helper function executes the specified encryption/decryption type and writes to a file encryption/decryption stat
def _execute_and_write_info(data, key, char_set, output_location, package, module, encrypt_decrypt):
    """
    This function executes the specified encryption/decryption method

    :param data: (string) the data to be encrypted/decrypted
    :param key: (string) the key to encrypt/decrypt with
    :param char_set: (string) the character set to be used
    :param output_location: (string) the location to write statistics and relevant information to
    :param package: (string) the package in which our encryption method is located in
    :param module: (string) the module in which our encryption method is located in
    :param encrypt_decrypt: (string) specifies encryption or decryption
    :return: (string) the encrypted/decrypted text
    """

    # START THE TIMER
    start_time = time.time()

    # Obtain num_chars to use in the encryption method
    num_chars = char_set_to_char_set_size.get(char_set)

    # EXECUTE THE ENCRYPTION/DECRYPTION METHOD
    exec("from " + package + " import " + module)
    encrypted = eval(module + "." + encrypt_decrypt + "(data, key, num_chars)")

    #  END THE TIMER
    elapsed_time = time.time() - start_time


    #  WRITE TO A NEW FILE CONTAINING RELEVANT INFO
    new_file = open(output_location + "_(Relevant information)", "w", encoding="utf-8")
    new_file.writelines(["The encryption/decryption type is: " + module,
                         "\nThe character set is : " + char_set,
                         "\nThe key is: " + key,
                         "\n" + encrypt_decrypt + "ed in: " + str(elapsed_time) + " seconds.",
                         "\n    That is " + str((elapsed_time / len(encrypted) )) + " seconds per character."
                         "\n    That is " + str((elapsed_time/len(encrypted) * 1000000))
                                          + " microseconds per character."])
    new_file.close()

    return encrypted


# This helper function executes the decryption types without a key and writes stats and info to a file
def _execute_and_write_info_no_key(data, output_location, package, module, encrypt_decrypt):
    """
    This function executes the correct decryption method. This also figures out the key and char set and writes info to
    a file

    :param data: (string) the cipher text to decrypt
    :param output_location: (string) the file to write info into
    :param package: (string) the package that the decryption function is located in
    :param module: (string) the module that the decryption function is in
    :return: (string) the decrypted text
    """


    # START THE TIMER and decrypt
    start_time = time.time()
    exec("from " + package + " import " + module)
    deciphered, char_set, key = eval(module + ".decrypt(data)")
    elapsed_time = time.time() - start_time


    #  WRITE TO A NEW FILE CONTAINING RELEVANT INFO
    new_file = open(output_location + "_(Relevant information)", "w", encoding="utf-8")
    new_file.writelines(["The decryption type is: " + module,
                         "\nThe character set is : " + char_set,
                         "\nThe key is: " + key,
                         "\n" + encrypt_decrypt + "ed in: " + str(elapsed_time) + " seconds.",
                         "\n    That is " + str((elapsed_time / len(deciphered) )) + " seconds per character."
                         "\n    That is " + str((elapsed_time/len(deciphered) * 1000000))
                                      + " microseconds per character."])
    new_file.close()

    return deciphered





















