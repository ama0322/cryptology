import time # for timing
import datetime # for labelling the date that files are created
import miscellaneous
import os # for deleting files




############################################################################################## MANUAL TESTING ##########

# MODIFY THESE VALUES
plaintext_source = "Library/Eleonora.txt"

char_set_size = miscellaneous.char_set_to_char_set_size.get("unicode_plane0")
key = "This is a key for testing"



encoding_scheme = "base64"




# This function enters the testing mode where the user can enter commands to see check ciphers and see stats
def testing_mode():

    # Forever while loop to take in user commands and execute them
    while True:

        # Get information necessary for encrypting and decryption
        encryption, decryption, plaintext, output_location, encryption_key, alphabet = _get_testing_info()

        # Pass this info to decryption's testing_execute
        exec("import Decryption." + decryption)
        exec("Decryption." + decryption
             + ".testing_execute(encryption, decryption, plaintext, encryption_key, alphabet, output_location)")










# Obtain information necessary to conduct encryption and decryption
def _get_testing_info():

    # Values to return
    encryption = ""
    decryption = ""
    plaintext = ""
    output_location = ""
    encryption_key = key                                    # Modify key as needed for the chosen cipher
    alphabet = ""                                           # num for char sets, name for encoding scheme

    # Get the decryption type and the encryption type (same name as decyption but w/o "_nokey")
    decryption = _parse_user_input()
    encryption = decryption if decryption.find("_nokey") == -1 else decryption[0: -6]

    # Obtain the plaintext
    my_file = open(plaintext_source, "r", encoding="utf-8")
    plaintext = my_file.read()
    my_file.close()

    # Create the output location for this run
    now = datetime.datetime.now()
    output_location = "Files_Logs/" + decryption + "_" + now.strftime("%Y-%m-%d_h%Hm%Ms%S")


    # Figure out the correct key to use (read key_size)
    # "zero characters"               is an encrypting cipher that doesn't need a key input
    # "calculated characters"         is a decrypting cipher that finds the key automatically
    # "single character"              is a symmetric encrypting/decrypting cipher that uses a single user-entered
    #                                 character
    # "multiple characters"           is an symmetric encrypting/decrypting cipher that uses user-entered string
    # "multiple generated characters" is a symmetric encrypting/decrypting cipher that uses randomly generated chars
    exec("import Decryption." + decryption)                               # Import module to read cipher properties
    key_size =    eval("Decryption." + decryption + ".key_size")          # The size of the key used (see comment above)
    alphabet =    eval("Decryption." + decryption + ".alphabet")          # Alphabet used
    cipher_type = eval("Decryption." + decryption + ".cipher_type")       # Symmetric or asymmetric


    if cipher_type == "symmetric":
        if key_size ==     "zero characters":
            encryption_key = ""

        elif key_size.find("calculated characters") != -1:                # If calculated, read on
            if key_size[22:] == "(single character)": encryption_key = key[0]
            elif key_size[22:] == "(multiple characters)": encryption_key = key
            elif key_size[22:] == "(multiple generated characters)": encryption_key = ""

        elif key_size ==   "single character":
            encryption_key = key[0]

        elif key_size ==   "multiple characters":
            encryption_key = key

        elif key_size ==   "multiple generated characters":               # Key is generated for us
            encryption_key = ""


    elif cipher_type == "asymmetric":                                     # Key is generated for us
        encryption_key = ""


    # Figure out the alphabet to use
    if alphabet == miscellaneous.char_encoding_schemes:                   # If encoding scheme, just return name
        alphabet = encoding_scheme
    elif alphabet == miscellaneous.char_sets:                             # If char set, return the size of the set
        alphabet = char_set_size


    return encryption, decryption, plaintext, output_location, encryption_key, alphabet




# Obtain commands from the user
def _parse_user_input():
        """
        This prompts the user and reads user info. The user may choose to change the default ciphertext location by
        entering "set " followed by the file of the ciphertext. Otherwise, the user specifies a decryption method to
        test

        :return: (string) the decryption method to test
        """

        # Prompt the user for a command
        statement = input("Enter a testing mode command: ")

        # Loop until the user enters a legitimate decryption type
        while True:

                # split the statement into an array of words
                command = statement.split()

                # If empty, continue
                if statement == "":
                        statement = input("No command entered! Enter a testing mode command: ")
                        continue

                # Check if the user decides to clear logs
                if command[0] == "clear":
                        # delete files in /Files_Logs
                        for file in os.listdir("Files_Logs"):
                                os.unlink("Files_Logs/" + file)

                        statement = input("Logs cleared. Enter a testing mode command: ")
                        continue



                # Check that the command is a legitimate decryption type. If so, break out of loop
                if statement in miscellaneous.decryption_set:
                        break

                # Prompt the user for a command again
                statement = input("Invalid command! Enter a testing mode command: ")

        return statement














########################################################################################### AUTOMATED TESTING ##########