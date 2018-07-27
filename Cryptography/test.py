from Cryptography import misc


import datetime                                  # for labelling the date that files are created
import os                                        # for deleting files




############################################################################################## MANUAL TESTING ##########

# MODIFY THESE VALUES
plaintext_source = "Resources/Library/Clarissa.txt"



alphabet_size = misc.CHAR_SET_TO_SIZE.get("ascii")
key = "This is a key for testing"


encoding_scheme = "base64"




# This function enters the testing mode where the user can enter commands to see check ciphers and see stats
def manual_testing(given_cipher):
    """
    Mode for manual testing.

    :param given_cipher: (string) May be empty string. Otherwise, run testing on what is given.
    :return:
    """


    # Run if the user has provided more args in addition to just entering test mode (test <cipher>, test clear, etc.)
    def handle_first_command(given_cipher):

        # Check that given_cipher is not empty ("")
        if given_cipher == "":
            return ""

        # Otherwise, run the command
        def get_testing_info_with_command(command):

            # Values to return
            encryption = ""
            decryption = ""
            plaintext = ""
            output_location = ""
            encryption_key = key  # Modify key as needed for the chosen cipher
            char_set = ""  # num for ALPHABETS, name for encoding scheme

            # Get the decryption type and the encryption type (same name as decryption but w/o "_nokey")
            def parse_user_input_with_command(command):
                """
                This prompts the user and reads user info. The user may choose to change the default ciphertext location
                by entering "set " followed by the file of the ciphertext. Otherwise, the user specifies a decryption
                method to test.
                Note, this does not handle "-a" because "-a" flag is handled in cryptography_runner.py

                :return: (string) the decryption method to test
                """

                # Prompt the user for a command
                statement = command

                # Loop until the user enters a legitimate decryption type
                while True:

                    # split the statement into an array of words
                    command = statement.split()

                    # If empty, continue
                    if statement == "":
                        statement = input("No command entered! Enter a testing mode command: "
                                          + "\u001b[32m" + "test " + "\u001b[0m")                   # test colored green
                        continue

                    # If exit, exit
                    if statement == "-e":
                        return None


                    # Check if the user decides to clear logs
                    if command[0] == "clear":
                        # delete files in /Files_Logs
                        for file in os.listdir("Resources/Files_Logs"):
                            os.unlink("Resources/Files_Logs/" + file)

                        statement = input("Logs cleared! Enter a testing mode command: "
                                          + "\u001b[32m" + "test " + "\u001b[0m")                   # test colored green
                        continue

                    # Check that the command is a legitimate decryption type. If so, break out of loop
                    if statement in misc.DECRYPTION_SET:
                        break

                    # Prompt the user for a command again
                    statement = input("Invalid command (" + statement + ")! Enter a testing mode command: "
                                      + "\u001b[32m" + "test " + "\u001b[0m")                       # test colored green

                return statement
            decryption = parse_user_input_with_command(command)

            # If decryption is None, indicating to exit, then, return None, None, None, None, None, None
            if decryption is None:
                return None, None, None, None, None, None,

            encryption = decryption if decryption.find("_nokey") == -1 else decryption[0: -6]

            # Obtain the plaintext
            my_file = open(plaintext_source, "r", encoding="utf-8")
            plaintext = my_file.read()
            my_file.close()

            # Create the output location for this run
            now = datetime.datetime.now()
            output_location = "Resources/Files_Logs/" + decryption + "_" + now.strftime("%Y-%m-%d_h%Hm%Ms%S")

            # Figure out the correct key to use (read key_size)
            # "zero characters"               is an encrypting cipher that doesn't need a key input
            # "calculated characters"         is a decrypting cipher that finds the key automatically
            # "single character"              is a symmetric encrypting/decrypting cipher that uses a single user-entered
            #                                 character
            # "multiple characters"           is an symmetric encrypting/decrypting cipher that uses user-entered string
            # "multiple generated characters" is a symmetric encrypting/decrypting cipher that uses randomly generated chars
            exec("import Decryption." + decryption)  # Import module to read cipher properties
            key_size = eval("Decryption." + decryption + ".key_size")  # The size of the key used (see comment above)
            char_set = eval("Decryption." + decryption + ".char_set")  # char_set used
            cipher_type = eval("Decryption." + decryption + ".cipher_type")  # Symmetric or asymmetric

            if cipher_type == "symmetric":
                if key_size == "zero characters":
                    encryption_key = ""

                elif key_size.find("calculated characters") != -1:  # If calculated, read on
                    if key_size[22:] == "(single character)":
                        encryption_key = key[0]
                    elif key_size[22:] == "(multiple characters)":
                        encryption_key = key
                    elif key_size[22:] == "(multiple generated characters)":
                        encryption_key = ""

                elif key_size == "single character":
                    encryption_key = key[0]

                elif key_size == "multiple characters":
                    encryption_key = key

                elif key_size == "multiple generated characters":  # Key is generated for us
                    encryption_key = ""


            elif cipher_type == "asymmetric":  # Key is generated for us
                encryption_key = ""

            # Figure out the char_set to use
            if char_set == misc.BINARY_TO_CHAR_ENCODING_SCHEMES:  # If encoding scheme, just return name
                char_set = encoding_scheme
            elif char_set == misc.ALPHABETS:  # If alphabet, return the size of the set
                char_set = alphabet_size

            return encryption, decryption, plaintext, output_location, encryption_key, char_set
        e, d, p, o_l, e_k, c_s = get_testing_info_with_command(given_cipher)

        # If return was None, None, ... then exit back to cryptography runner
        if e is None:
            return None

        # Pass this info to decryption's testing_execute
        exec("import Decryption." + d)
        exec("Decryption." + d
                + ".testing_execute(e, d, p, plaintext_source, "
                + "                 e_k, c_s, o_l)")
    handle_first_command(given_cipher)



    # Forever while loop to take in user commands and execute them
    while True:

        # Get information necessary for encrypting and decryption
        encryption, decryption, plaintext, output_location, encryption_key, char_set = _get_testing_info()


        # If _get_testing_info() output is all None's, then exit this function back to Cryptography_runner
        if encryption is None:
            return

        # Else, proceed regularly. Pass this info to decryption's testing_execute
        else:
            exec("import Decryption." + decryption)
            exec("Decryption." + decryption
                + ".testing_execute(encryption, decryption, plaintext, plaintext_source, "
                + "                 encryption_key, char_set, output_location)")







# Obtain information necessary to conduct encryption and decryption
def _get_testing_info():

    # Values to return
    encryption = ""
    decryption = ""
    plaintext = ""
    output_location = ""
    encryption_key = key                                    # Modify key as needed for the chosen cipher
    char_set = ""                                           # num for ALPHABETS, name for encoding scheme

    # Get the decryption type and the encryption type (same name as decryption but w/o "_nokey")
    decryption = _parse_user_input()
    if decryption is None:                # If the output (decryption) is None indicating "exit", return None, None, ...
        return None, None, None, None, None, None
    else:                                                     #Otherwise, proceed as necessary
        encryption = decryption if decryption.find("_nokey") == -1 else decryption[0: -6]

    # Obtain the plaintext
    my_file = open(plaintext_source, "r", encoding="utf-8")
    plaintext = my_file.read()
    my_file.close()

    # Create the output location for this run
    now = datetime.datetime.now()
    output_location = "Resources/Files_Logs/" + decryption + "_" + now.strftime("%Y-%m-%d_h%Hm%Ms%S")


    # Get the encryption key
    encryption_key = _obtain_encryption_key(decryption)


    # Figure out the char_set to use
    exec("from Cryptography.Decryption import " + decryption)
    char_set = eval(decryption + ".char_set")                              # char_set used
    if char_set == misc.BINARY_TO_CHAR_ENCODING_SCHEMES:                   # If encoding scheme, just return name
        char_set = encoding_scheme
    elif char_set == misc.ALPHABETS:                             # If alphabet, return the size of the alphabet
        char_set = alphabet_size


    return encryption, decryption, plaintext, output_location, encryption_key, char_set



# Obtain the key to use in encryption (and maybe decryption)
def _obtain_encryption_key(decryption_cipher):
    """
    Function that determines that key to use based on the decryption_cipher

    :param decryption_cipher: (string) the name of the decryption_cipher to use
    :return: (string) The key to use in encryption (May end up to be empty in certain cases; e.g. RSA)
    """

    # Figure out the correct key to use (read key_size)
    # "zero characters"               is an encrypting cipher that doesn't need a key input
    # "calculated characters"         is a decrypting cipher that finds the key automatically
    # "single character"              is a symmetric encrypting/decrypting cipher that uses a single user-entered
    #                                 character
    # "multiple characters"           is an symmetric encrypting/decrypting cipher that uses user-entered string
    # "multiple generated characters" is a symmetric encrypting/decrypting cipher that uses randomly generated chars
    exec("import Decryption." + decryption_cipher)                             # Import module to read cipher properties
    key_size =    eval("Decryption." + decryption_cipher + ".key_size")        # The size of the key used (see notes)
    char_set =    eval("Decryption." + decryption_cipher + ".char_set")        # char_set used
    cipher_type = eval("Decryption." + decryption_cipher + ".cipher_type")     # Symmetric or asymmetric


    encryption_key = ""                          # Fill this in

    if cipher_type == "symmetric":
        if key_size ==     "zero characters":
            encryption_key = ""

        elif key_size.find("calculated characters") != -1:                                  # If calculated, read on
            if key_size[22:] == "(single character)": encryption_key = key[0]
            elif key_size[22:] == "(multiple characters)": encryption_key = key
            elif key_size[22:] == "(multiple generated characters)": encryption_key = ""

        elif key_size ==   "single character":
            encryption_key = key[0]

        elif key_size ==   "multiple characters":
            encryption_key = key

        elif key_size ==   "multiple generated characters":                                 # Key is generated for us
            encryption_key = ""


    elif cipher_type == "asymmetric":                                                       # Key is generated for us
        encryption_key = ""


    return encryption_key


# Obtain commands from the user
def _parse_user_input():
        """
        This prompts the user and reads user info. The user may choose to change the default ciphertext location by
        entering "set " followed by the file of the ciphertext. Otherwise, the user specifies a decryption method to
        test

        :return: (string) the decryption method to test
        """

        # Prompt the user for a command
        statement = input("Enter a testing mode command: "
                          + "\u001b[32m" + "test " + "\u001b[0m")  # test colored green

        # Loop until the user enters a legitimate decryption type
        while True:

                # split the statement into an array of words
                command = statement.split()

                # If empty, continue
                if statement == "":
                    statement = input("No command entered! Enter a testing mode command: "
                                        + "\u001b[32m" + "test " + "\u001b[0m")                   # test colored green
                    continue

                # If automated, then run that, and take next command
                if statement == "-a":
                    automated_testing()
                    statement = input("Automated tests done! Enter a testing mode command: "
                                        + "\u001b[32m" + "test " + "\u001b[0m")                   # test colored green
                    continue

                # If "exit", then return None:
                if statement == "-e":
                    return None

                # Check if the user decides to clear logs
                if command[0] == "clear":

                    for file in os.listdir("Resources/Files_Logs"):                  # delete files in /Files_Logs
                        os.unlink("Resources/Files_Logs/" + file)

                    statement = input("Logs cleared! Enter a testing mode command: "
                                        + "\u001b[32m" + "test " + "\u001b[0m")                   # test colored green
                    continue



                # Check that the command is a legitimate decryption type. If so, break out of loop
                if statement in misc.DECRYPTION_SET:
                    break

                # Prompt the user for a command again
                statement = input("Invalid command (" + command[0] + ")! Enter a testing mode command: "
                                    + "\u001b[32m" + "test " + "\u001b[0m")  # test colored green

        return statement














########################################################################################### AUTOMATED TESTING ##########


# Random characters. Use this for testing.
plaintext_sample = """
extremely concerned, my dearest friend, for the disturbances that have happened in your family. I know how it must hurt
you to become the subject of the public ﾶ talk: and yet, upon an occasion so generally known, it is impossible but that
whatever relates to a young  treatment they gave him when he went ん And yet that other, although in unbosoming himself
to a select friend, he discovers wickedness enough to entitle him to general detestation, preserves a decency, as well
in his images as in his language, which is not always to be found in the works of some of the most celebrated modern
writers, whose subjects and characters have less warranted the liberties they have taken.

In the letters of the two ん young ladies, it is presumed, will be found not only the highest exercise of a reasonable
and practicable friendship, between minds endowed with the noblest principles of virtue and religion, but occasionally
interspersed, such delicacy of sentiments, particularly with regard to the other sex; such instances of impartiality,
each freely, as a fundamental principle of their friendship, blaming, praising, and setting right the other, as are
strongly to be recommended to the observation of the younger part (more specially) of female readers.
"""



# This function automatically checks all the ciphers (may take some time) Needs to be as optimized as possible
def automated_testing():
    """
    This will test all of the Decryption ciphers by:
        1: Encrypt with the corresponding encryption cipher
        2: Decrypt with the Decryption cipher
        3: Checking the decrypted text against the original plaintext

    Run tests with all Decryption ciphers, ALPHABETS/encoding_schemes, and different* plaintext lengths (for blocks),
    and also plaintexts of different character sets.
    While testing is conducted, print out the results.
    *In general, use short text so that the test doesn't take too long.

    :return: None
    """


    # ADD HERE. Use smaller key sizes on ciphers to save time
    from Cryptography.Decryption import rsa
    rsa_original = rsa.key_bits; rsa.key_bits = 512


    # Build up plaintext. Need different lengths and character sets
    testing_plaintexts = [plaintext_sample[:10], plaintext_sample[:100], plaintext_sample[:1000]]


    # Store incorrect ciphers here.
    incorrect_ciphers = []


    # FOR ALL DECRYPTION CIPHERS, test them
    for decrypt_cipher in misc.DECRYPTION_SET:

        # Figure out which encrypting cipher to use (same name, but without "_nokey" if it exists)
        encrypt_cipher = decrypt_cipher if decrypt_cipher.find("_nokey") == -1 else decrypt_cipher[0: -6]

        # Figure out the encrypting key to use
        encrypt_key = _obtain_encryption_key(decrypt_cipher)

        # Figure out whether to use alphabet or character encoding scheme
        exec("from Cryptography.Decryption import " + decrypt_cipher)
        character_sets = eval(decrypt_cipher + ".char_set")


        # FOR ALL THE ALPHABETS/CHARACTER_ENCODING_SCHEMES
        for char_set in character_sets:


            # If char_set uses alphabet_size, then calculate that
            if char_set in misc.ALPHABETS:
                char_set = misc.CHAR_SET_TO_SIZE.get(char_set)



            # FOR ALL OF THE PLAINTEXTS TO TEST
            for plaintext in testing_plaintexts:

                # If decrypt_cipher does not allow short texts, then skip the short texts
                try:
                    if eval(decrypt_cipher + ".no_short_texts") == True:
                        continue
                except Exception:                                        # Short texts allowed, do nothing
                    pass

                # Adjust the character set if necessary. Some ciphers cannot work correctly if the chosen ciphertext
                # alphabet is smaller than the plaintext's alphabet. They require at minimum the plaintext's alphabet to
                # decrypt correctly. So switch to use the plaintext's alphabet for encryption, and inform the user
                exec("from Cryptography.Decryption import "
                     + decrypt_cipher)
                try:
                    restrict = eval(decrypt_cipher                       # Ciphertext alphabet restricted
                                    + ".ciphertext_alphabet_restricted")
                    if restrict == True:                                 # Restrict by using plaintext's alphabet.
                        alphabet = misc.alphabet_of(plaintext)
                        char_set = misc.CHAR_SET_TO_SIZE.get(alphabet)
                        print("The chosen alphabet for encryption is"
                              + " insufficient for the alphabet that"
                              + " the plaintext's alphabet is in."
                              + "\nTherefore, the alphabet for"
                              + " encryption is switched to: "
                              + alphabet)

                except Exception:                                       # Ciphertext alphabet not restricted. Do nothing
                    pass


                # Run the ENCRYPTION, and parse the output (may be a tuple) to get ciphertext and key
                exec("import Cryptography.Encryption."
                     + encrypt_cipher)
                encryption_output = eval("Cryptography.Encryption."  # Run encryption
                                         + encrypt_cipher
                                         + ".encrypt(plaintext, encrypt_key, char_set)")
                ciphertext  = ""    # Fill this in
                decrypt_key = ""    # Fill this in

                # Parse the output of the encryption to figure out ciphertext and decrypt_key
                if type(encryption_output) is tuple:    # If tuple, then ciphertext is 1st index
                    ciphertext = encryption_output[0]

                    if len(encryption_output) == 3:     # Len 3 indicates asymmetric keys made
                        decrypt_key = encryption_output[2]

                    elif len(encryption_output) == 2:   # Len 2 indicates symmetric key generated
                        decrypt_key = encryption_output[1]

                else:                                   # Not tuple, just regular ciphertext
                    ciphertext = encryption_output
                    decrypt_key = encrypt_key




                # Run DECRYPTION, save time and decrypted text
                try:                                                           # Run decryption
                    decrypted = ""
                    exec("from Cryptography.Decryption import "                # Import module for decryption
                            + decrypt_cipher)
                    decryption_output = eval(decrypt_cipher                    # Run the actual decryption
                            + ".decrypt(ciphertext, decrypt_key, char_set)")
                    if type(decryption_output) is tuple:                       # If tuple, then decrypted is 1st index
                        decrypted = decryption_output[0]
                    else:                                                      # Otherwise, decrypted is the only output
                        decrypted = decryption_output

                    # Check if the decrypted text is same as plaintext and add to graph
                    if decrypted != plaintext:
                        incorrect_ciphers.append(decrypt_cipher + " (I)")
                except:                                                   # Catch all exceptions, because decrypt wrong
                    incorrect_ciphers.append(decrypt_cipher + " (F)")
                    continue




    # Print out incorrect ciphers (may be duplicates)
    incorrect_ciphers.sort()
    print("𝓘𝓝𝓒𝓞𝓡𝓡𝓔𝓒𝓣 𝓒𝓘𝓟𝓗𝓔𝓡𝓢 ", end="")
    print(*incorrect_ciphers, sep=", ")




    # ADD HERE. Undo the temporary key size changes
    rsa.key_bits = rsa_original