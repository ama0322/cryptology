from Cryptography.Ciphers._cipher import          Cipher   # To get the abstract superclass
from Cryptography.Ciphers         import *                 # To construct Cipher objects
from Cryptography                 import misc              # To get misc functions
import                                   datetime          # for labelling the date that files are created
import                                   os                # for deleting files




########################################################################################### PRIMARY FUNCTIONS ##########

# MODIFY THESE VALUES
testing_plaintext_source                 = "Resources/Library/Eleonora"

testing_key                              = "This is a key for testing"
testing_key_size                         = 0
testing_block_size                       = 0

testing_encoding_scheme                  = "extended_ascii"
testing_alphabet                         = "ascii"

testing_mode_of_operation                = "cbc"






def manual_testing(statement:str) -> None:
    """
    The given_command is everything that follows the "test ". Read this to figure out what to do.

    :param statement: (str)  The command
    :return:          (None)
    """


    # This function will parse the user "test" statement
    def parse_user_input(statement:str) -> str or None:
        """
        Parses user input. If the user wishes to exit, then this function returns None. If the user gives a
        legitimate cipher, then the test for that cipher will run

        :param statement: (str) The statement to process
        :return:          (str or None) Gives the name of the cipher to test, or None to exit this function
        """
        # If the statement is empty, then ask the user for a command
        if statement == "":
            statement = input("Enter a testing mode command: {}test {}".format("\u001b[32m", "\u001b[0m"))

        # Loop until the given_command is a legitimate command
        while True:
            # split the statement into an array of words
            command = statement.split()

            # If empty, continue
            if statement == "":
                # region Handle empty command
                statement = input("No command entered! Enter a testing mode command: "
                                  + "\u001b[32m" + "test " + "\u001b[0m")  # test colored green
                continue
                # endregion

            # If automated, then run that, and take next command
            if command[0] == "-a":
                # region Handle automated test command
                # If there is stuff afterwards, is an error
                if statement.rstrip(" ") != "-a":
                    statement = input("Extraneous arguments \"{}\"! Enter a testing mode command: "
                                      "{}test {}".format(statement[statement.find("-e") + 3:], "\u001b[32m",
                                                         "\u001b[0m"))
                    continue


                automated_testing()
                statement = input("Automated tests done! Enter a testing mode command: "
                                  + "\u001b[32m" + "test " + "\u001b[0m")  # test colored green
                continue
                # endregion

            # If "exit", then return None:
            if command[0] == "-e":
                # region Handle exit command
                # If there is stuff afterwards, is an error
                if statement.rstrip(" ") != "-e":
                    statement = input("Extraneous arguments \"{}\"! Enter a testing mode command: "
                                      "{}test {}".format(statement[statement.find("-e") + 3:], "\u001b[32m",
                                                         "\u001b[0m"))
                    continue


                return None
                # endregion

            # Check if the user decides to clear logs
            if command[0] == "-c":
                # region Handle clear command
                # If there is stuff afterwards, is an error
                if statement.rstrip(" ") != "-c":
                    statement = input("Extraneous arguments \"{}\"! Enter a testing mode command: "
                                      "{}test {}".format(statement[statement.find("-c") + 3:], "\u001b[32m",
                                                         "\u001b[0m"))
                    continue

                for file in os.listdir("Resources/Files_Logs"):  # delete files in /Files_Logs
                    os.unlink("Resources/Files_Logs/" + file)

                statement = input("Testing logs cleared! Enter a testing mode command: "
                                  + "\u001b[32m" + "test " + "\u001b[0m")  # test colored green
                continue
                # endregion

            # Check that the command is a legitimate decryption type. If so, break out of loop
            if statement.rstrip(" ") in Cipher.DECRYPTION_SET:
                # region Handle legitimate cipher command
                return statement.rstrip(" ")
                # endregion

            # Else, Prompt the user for a command again
            else:
                # region Handle invalid command
                statement = input("Invalid command \"" + command[0] + "\"! Enter a testing mode command: "
                                                                      "\u001b[32m" + "test " + "\u001b[0m")
                # endregion
    chosen_cipher = parse_user_input(statement)

    # If the user typed "-e", the parse_user_input() returns None, indicating to return back to cryptography_runner
    if chosen_cipher is None:
        return None



    # Generate the cipher object and save the original plaintext (for comparison against the decrypt() output)
    cipher_obj = _get_testing_info(chosen_cipher)
    test_result = _conduct_test_and_write_stats(cipher_obj)



    # Print test success/failure
    if test_result == True:                                  # If correct, then print green CORRECT
        print("{}: {}𝐂𝐎𝐑𝐑𝐄𝐂𝐓{}".format(misc.get_class_name(chosen_cipher), "\u001b[32m", "\u001b[0m"))
    else:                                                    # If incorrect, then print red CORRECT
        print("{}: {}𝐈𝐍𝐂𝐎𝐑𝐑𝐄𝐂𝐓{}".format(misc.get_class_name(chosen_cipher), "\u001b[31m", "\u001b[0m"))


    # Enter back into the testing mode
    statement = input("\n{} testing done! Enter another testing mode command: {}test {}"
                      .format(misc.get_class_name(chosen_cipher), "\u001b[32m", "\u001b[0m"))
    return manual_testing(statement)




def automated_testing() -> None:
    """
    Runs testing on all ciphers, with all combinations

    :return: (None)
    """



    # Store the original global vars. Will reset back to this at the end of the automated_testing()
    global testing_key_size
    global testing_block_size
    global testing_encoding_scheme
    global testing_alphabet
    global testing_mode_of_operation
    global testing_plaintext_source
    original_testing_encoding_scheme   = testing_encoding_scheme
    original_testing_alphabet          = testing_alphabet
    original_testing_mode_of_operation = testing_mode_of_operation
    original_testing_plaintext_source  = testing_plaintext_source
    original_testing_key_size          = testing_key_size
    original_testing_block_size        = testing_block_size

    # Random characters. Use this for testing.
    plaintext_sample = \
    """I AM come of a race noted for vigor of fancy and ardor of passion. Men have called me mad; but the question is not yet settled, whether madness is or is not the loftiest intelligence—whether much that is glorious—whether all that is profound—does not spring from disease of thought—from moods of mind exalted at the expense of the general intellect. They who dream by day are cognizant of many things which escape those who dream only by night. In their gray visions they obtain glimpses of eternity, and thrill, in awakening, to find that they have been upon the verge of the great secret. In snatches, they learn something of the wisdom which is of good, and more of the mere knowledge which is of evil. They penetrate, however, rudderless or compassless into the vast ocean of the “light ineffable,” and again, like the adventures of the Nubian geographer, “agressi sunt mare tenebrarum, quid in eo esset exploraturi.” We will say, then, that I am mad. I grant, at least, that there are two distinct conditions of my mental existence—the condition of a lucid reason, not to be disputed, and belonging to the memory of events forming the first epoch of my life—and a condition of shadow and doubt, appertaining to the present, and to the recollection of what constitutes the second great era of my being. Therefore, what I shall tell of the earlier period, believe; and to what I may relate of the later time, give only such credit as may seem due, or doubt it altogether, or, if doubt it ye cannot, then play unto its riddle the Oedipus. """

    # Build up plaintext. Need different lengths and character sets. Save to Resources. Delete them at the end
    testing_plaintexts = ["plaintext_sample[0:10]", "plaintext_sample[0:100]", "plaintext_sample[0:1000]"]
    for file_name in testing_plaintexts:
        sample_file = open("Resources/" + file_name, "w", encoding="utf-8")
        text = eval(file_name)
        sample_file.write(text)
        sample_file.close()


    # Store incorrect ciphers here
    incorrect_ciphers = []

    # Figure out how many tests will be run
    total_tests = 0
    misc.disable_print()
    for decrypt_cipher in Cipher.DECRYPTION_SET:
        # Figure out whether to use alphabet or encoding scheme
        if eval("{}.{}.CHAR_SET".format(decrypt_cipher, misc.get_class_name(decrypt_cipher))) == "alphabet":
            char_sets = Cipher.ALPHABETS
        else:
            char_sets = Cipher.ENCODING_SCHEMES
        for char_set, plaintext, mode_of_op in [(x, y, z) for x in char_sets
                                                          for y in testing_plaintexts
                                                          for z in Cipher.MODES_OF_OPERATION]:
            # If doesn't use mode of operation, then just continue if the mode has already been tested
            if eval("{}.{}.IS_BLOCK_CIPHER".format(decrypt_cipher, misc.get_class_name(decrypt_cipher))) is False:
                # If has already been run once (past the "ecb", which is the first choice), then skip
                if mode_of_op != "ecb":
                    continue
            # If requires english, then skip the short 10 length one
            if eval("{}.{}.NEEDS_ENGLISH".format(decrypt_cipher, misc.get_class_name(decrypt_cipher))) is True \
                                                                                               and len(plaintext) < 100:
                continue

            # ONE TEST IS RUN HERE
            total_tests += 1
    misc.enable_print()







    # A counter for the number of tests run
    tests_run = 0

    # For all ciphers, test them
    for decrypt_cipher in Cipher.DECRYPTION_SET:

        # Figure out whether to use alphabet or encoding scheme
        if eval("{}.{}.CHAR_SET".format(decrypt_cipher, misc.get_class_name(decrypt_cipher))) == "alphabet":
            char_sets = Cipher.ALPHABETS
        else:
            char_sets = Cipher.ENCODING_SCHEMES

        # Test all the different character sets, mode of operation, and different plaintexts
        for char_set, plaintext, mode_of_op in [(x, y, z) for x in char_sets
                                                          for y in testing_plaintexts
                                                          for z in Cipher.MODES_OF_OPERATION]:

            # If doesn't use mode of operation, then just continue if the mode has already been tested
            if eval("{}.{}.IS_BLOCK_CIPHER".format(decrypt_cipher, misc.get_class_name(decrypt_cipher))) is False:
                # If has already been run once (past the "ecb", which is the first choice), then skip
                if mode_of_op != "ecb":
                    continue
                # Also, set the name of "ecb" to empty space "   "
                mode_of_op = ""

            # If requires english, then skip the short 10 length one
            if eval("{}.{}.NEEDS_ENGLISH".format(decrypt_cipher, misc.get_class_name(decrypt_cipher))) is True \
                                                                                               and len(plaintext) < 100:
                continue


            # Set the global vars up above in preparation for _get_testing_info().
            testing_encoding_scheme   = char_set
            testing_alphabet          = char_set
            testing_mode_of_operation = mode_of_op
            testing_plaintext_source  = "Resources/" + plaintext
            testing_key_size          = eval("{}.{}.AUTO_TEST_KEY_SIZE".format(decrypt_cipher,
                                                                          misc.get_class_name(decrypt_cipher)))
            testing_block_size        = eval("{}.{}.AUTO_TEST_BLOCK_SIZE".format(decrypt_cipher,
                                                                              misc.get_class_name(decrypt_cipher)))

            # Create the cipher object and test it
            misc.disable_print()                                                             # Temporarily block print
            cipher_obj = _get_testing_info(decrypt_cipher)


            # Attempt to run the test. If encryption and decryption fails, print (f). If success, check correctness
            try:

                # Increase test counter
                tests_run += 1

                cipher_obj.encrypt_plaintext()
                cipher_obj.decrypt_ciphertext()
                misc.enable_print()                         # Enable print
                if cipher_obj.original_plaintext != cipher_obj.plaintext:    # If incorrect, print that out
                    incorrect_ciphers.append("{} (I) {} {} {}"
                                             .format(decrypt_cipher, char_set, mode_of_op, len(cipher_obj.plaintext)))
            except:                                                          # Cipher complete failure
                incorrect_ciphers.append("{} (I) {} {} {}".format(decrypt_cipher, char_set, mode_of_op,
                                                                  len(cipher_obj.plaintext)))


            # Print the percentage of automated tests done
            print("Percent done: {}{:.2%}{} \twith tests finished: {}{}/{}{}"
                  .format("\u001b[32m", tests_run / total_tests, "\u001b[0m",
                          "\u001b[32m",tests_run, total_tests, "\u001b[0m"))

    # Print out incorrect ciphers (may be duplicates)
    incorrect_ciphers.sort()
    print()
    print("An (F) indicates that the decryption failed to run correctly (some error raised during decryption).")
    print("An (I) indicates that the decryption produced an incorrect result (not the original plaintext)")
    print("𝓘𝓝𝓒𝓞𝓡𝓡𝓔𝓒𝓣 𝓒𝓘𝓟𝓗𝓔𝓡𝓢:\n", end="")
    if len(incorrect_ciphers) == 0: incorrect_ciphers.append("\u001b[32mNONE\u001b[0m")     # Colored green
    print(*incorrect_ciphers, sep="\n")
    print()



    # Build up plaintext. Need different lengths and character sets. Save to Resources. Delete them at the end
    for file_name in testing_plaintexts:
        try:
            os.remove("Resources/" + file_name)
            os.remove("Resources/plaintext_sample[0")
        except Exception:
            pass

    # Reset the global vars to their original values
    testing_encoding_scheme   = original_testing_encoding_scheme
    testing_alphabet          = original_testing_alphabet
    testing_mode_of_operation = original_testing_mode_of_operation
    testing_plaintext_source  = original_testing_plaintext_source
    testing_key_size          = original_testing_key_size
    testing_block_size        = original_testing_block_size

######################################################################################### ANCILLARY FUNCTIONS ##########


# This generates a cipher object for testing (takes encryption and decryption parameters from variables above)
def _get_testing_info(decrypt_cipher:str) -> Cipher:
    """
    Generate a cipher object for testing based on the testing settings variables up above.

    :param decrypt_cipher: (str)           The name of the decryption cipher to use
    :return:               (cipher.Cipher) The general object to return
    """


    # Specific variables to use during encryption/decryption. Fill in before using in construction of Cipher object
    plaintext       = ""        # FILL IN. The plaintext, needs to be set in variable above (in source file)
    ciphertext      = ""        # Leave empty
    char_set        = ""        # FILL IN. Will be an alphabet or an encoding scheme, set in variable above
    key             = ""        # FILL IN. For symmetric ciphers, automatically set. For block ciphers, is ""
    public_key      = ""        # For asymmetric ciphers, set to ""
    private_key     = ""        # For asymmetric ciphers, set to ""
    block_size      = 0         # For block ciphers, automatically set by the cipher class constructor
    key_size        = 0         # For block ciphers, automatically set by the cipher class constructor
    mode_of_op      = ""        # FILL IN. For block ciphers, set in variable above
    source_location = ""        # FILL IN. The source file for the data, set in variable above
    output_location = ""        # FILL IN. The output file to store the output, automatically created


    # The class name for the specific Cipher subclass object
    class_name = misc.get_class_name(decrypt_cipher)

    # Fill in the immediate and obvious variables
    source_location = testing_plaintext_source                                                     # source_location
    with open(source_location, "r", encoding="utf-8") as source_file:
        data = source_file.read()
    output_location = "Resources/Files_Logs/" + class_name + "_" \
                      + datetime.datetime.now().strftime("%Y-%m-%d_h%Hm%Ms%S")                     # output_location
    mode_of_op = testing_mode_of_operation                                                         # mode_of_op
    plaintext = data                                                                               # plaintext



    # Set a key for non-block alphabet ciphers
    if eval("{}.{}.CHAR_SET".format(decrypt_cipher, class_name)) == "alphabet":
        key_type = eval("{}.{}.KEY_TYPE".format(decrypt_cipher, class_name))
        if key_type.find("single character") != -1:           # Encryption uses a single character
            key = testing_key[0]
        elif key_type.find("multiple characters") != -1:      # Encryption uses multiple characters
            key = testing_key
        else:                                                 # Encryption generates its own key
            key = ""
    else:                                                     # Else, no need to manually set the key
        key = ""



    #  Set the character set
    if eval("{}.{}.CHAR_SET".format(decrypt_cipher, class_name)) == "alphabet":
        char_set = testing_alphabet
        char_set = misc.adjust_alphabet(data, char_set, "alphabet",                  # Adjust alphabet if necessary
                                        eval("{}.{}.RESTRICT_ALPHABET".format(decrypt_cipher, class_name)))
    else:
        char_set = testing_encoding_scheme



    # Set the key and block size
    key_size = testing_key_size
    block_size = eval("{}.{}.TEST_BLOCK_SIZE".format(decrypt_cipher, class_name))



    # Create the Cipher object
    cipher_obj = eval("{}.{}(plaintext, ciphertext, char_set, mode_of_op, key, public_key, private_key, "
                      "      block_size, key_size, source_location, output_location)"
                      .format(decrypt_cipher, class_name))


    return cipher_obj



# This writes to a file with the statistics about the encryption and decryption
def _conduct_test_and_write_stats(cipher_obj:Cipher) -> bool:
    """
    The cipher object to run encryption and then decryption. Write to a file detailing the statistics of encryption
    and decryption.

    :param cipher_obj: (_cipher.Cipher) The cipher object to encrypt and decrypt with
    :return:           (bool)           THe success or failure of the encryption and decryption
    """



    # Run the encryption, and then run the decryption
    cipher_obj.encrypt_plaintext()
    cipher_obj.decrypt_ciphertext()


    # Generate file name and write to that file containing the statistics of the encryption and decryption
    cipher_name = str(type(cipher_obj))
    cipher_name = cipher_name[cipher_name.rfind(".") + 1: -2]
    stats_file_path = "Resources/Files_Logs/{}__{}"\
                      .format(cipher_name, datetime.datetime.now().strftime("%Y-%m-%d_h%Hm%Ms%S"))
    cipher_obj.write_statistics(stats_file_path)


    # Return the correctness of the encryption and decryption
    return cipher_obj.original_plaintext == cipher_obj.plaintext





