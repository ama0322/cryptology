from Cryptography.Ciphers._cipher         import Cipher # To get access to Cipher objects
from Cryptography.Ciphers import *        # To construct Cipher objects

from Cryptography         import misc     # for miscellaneous functions
from Cryptography         import test     # for manual/automatic testing

import                           datetime # to be used in fileName
import                           os       # to delete files in decrypted and encrypted, directory stuff










last = "" # Store the path to the last created encrypted/decrypted file


###################################################################################### START OF MAIN FUNCTION ##########
def main() -> None:
    """
    This runs when the program runs. It takes commands and executes them.

    :return: (None)
    """

    # Set the current working directory to be the project "Cryptography", two levels above from this file.
    path_here = os.path.realpath(__file__)
    one_above = path_here[:path_here.rfind("\\")]
    two_above = path_here[:one_above.rfind("\\")]
    os.chdir(two_above)


    #  Print out info when the program first begins
    _usage()


    # Forever while loop to continually take in user input and executing commands
    while True:

        # Obtain information from the user command
        cipher, encrypt_or_decrypt, data, source_location, output_location = _parse_user_input()

        # Set up the global variable last for next iteration
        global last
        last = output_location

        # print out the data, and let the user know where the output location is
        _print_data_and_location( data, output_location )

        # execute the encryption/decryption on the data
        _execute_encryption_or_decryption( encrypt_or_decrypt, cipher, data, source_location, output_location )
######################################################################################## END OF MAIN FUNCTION ##########





# execute encryption/decryption on the data, save the output, and print out the output
def _execute_encryption_or_decryption( encrypt_or_decrypt:str, cipher_module:str, data:str,
                                       source_location:str, output_location:str ) -> None:
    """
    This will execute the encryption/decryption. The output, along with relevant information, is stored in the
    output_location.

    :param encrypt_or_decrypt: (str)  Either "encrypt" or "decrypt". Indicates which mode to use
    :param cipher_module:      (str)  The name of the cipher module to use
    :param data:               (str)  The data to encrypt or decrypt. Is either plaintext of ciphertext
    :param source_location     (str)  The name of the source of the data
    :param output_location:    (str)  The filepath to store the processed text
    :return:                   (None)
    """


    # Get the ClassName of the cipher. Is same but with CapWord convention instead of lower_case_with_underscores
    cipher_class_name = misc.get_class_name(cipher_module)


    # Create dummy object (to get access to class static variables)
    cipher_obj = eval("{}.{}(\"\", \"\", \"\", \"\", \"\", \"\", \"\", 0, 0, \"\", \"\")"
                      .format(cipher_module, cipher_class_name))


    # Specific variables to use during encryption/decryption. Fill in before using in construction of Cipher object
    plaintext       = ""                  # The plaintext, needs to be set during encryption
    ciphertext      = ""                  # The ciphertext, needs to be set during decryption
    char_set        = ""                  # An alphabet or encoding scheme, optionally provided by the user
    key             = ""                  # FOr symmetric ciphers, optionally provided by user
    public_key      = ""                  # For asymmetric ciphers, optionally provided by user
    private_key     = ""                  # FOr asymmetric ciphers, needs to be provided by user
    block_size      = 0                   # For ciphers that support variable block sizes, optionally provided by user
    key_size        = 0                   # For ciphers that support variable key sizes, optionally provided by the user
    mode_of_op      = ""                  # For block ciphers, optionally set by user
    source_location = source_location     # The source file for the data
    output_location = output_location     # The output file to store the output

    # Variables to fill after the encryption/decryption is done
    time           = 0.0
    processed_data = ""

    # Set the plaintext or ciphertext with data
    def set_plaintext_or_ciphertext() -> (str, str):
        """
        Set the plaintext or ciphertext.

        :return:                   (str) The plaintext
        :return:                   (str) The ciphertext
        """

        plaintext  = ""
        ciphertext = ""

        if encrypt_or_decrypt == "encrypt":
            plaintext = data

        else:
            ciphertext = data

        return plaintext, ciphertext

    # Figure out the specific char_set to use during encryption/decryption
    def get_char_set() -> str:
        """
        Get the character set to use during encryption/decryption

        :return: (str) The name of the character set
        """

        # Ask for the char_set
        def take_char_set() -> str:
            """
            This manually asks the user for a character set.

            :return: (str) The name of the character set that the user wants.
            """

            # Set the default character set and the available options, based on cipher_char_set
            if cipher_obj.CHAR_SET == "alphabet":
                default_selection = "unicode_plane0"
                options = Cipher.ALPHABETS
            else:
                default_selection = "base64"
                options = Cipher.ENCODING_SCHEMES

            # Print out the prompt for the user
            selection = input("Enter the %s to be used for the ciphertext (or to use the default alphabet, \"%s\", "
                              "leave empty): " % (cipher_obj.CHAR_SET, default_selection))

            # Loop while the user gives an invalid alphabet. If valid, then break
            while True:

                # If the user asks for help
                if selection == "info":
                    print("The available %ss are: " % cipher_obj.CHAR_SET, end="")
                    for option in options:

                        if option == "ascii":
                            print(" " * (45 - len("The available Cipher.ALPHABETS are: ")) + option)

                        elif option == "base16":
                            print(" " * (45 - len("The available encoding schemes are: ")) + option)

                        else:
                            print(" " * 45 + option)

                    selection = input(
                        "\nEnter the %s to be used for the ciphertext (or to use the default alphabet, \"%s\", "
                        "leave empty): " % (cipher_obj.CHAR_SET, default_selection))
                    continue

                # User wants default char_set
                elif selection == "":
                    selection = default_selection
                    break

                # Invalid option
                elif selection.rstrip() not in options:
                    selection = input("Invalid %s (%s)! Try again: " % (cipher_obj.CHAR_SET, selection.rstrip()))
                    continue

                # If here, then user gave valid option. All clear
                else:
                    break

            return selection


        # If encrypt, then ask for the char_set
        if encrypt_or_decrypt == "encrypt":

            # Get a char set
            chosen_char_set = take_char_set()

            # Adjust the alphabet (The function will handle non-adjustments also)
            return misc.adjust_alphabet(data, chosen_char_set, cipher_obj.CHAR_SET, cipher_obj.RESTRICT_ALPHABET)


        # Elif decrypt, try to figure out the char_set automatically
        elif encrypt_or_decrypt == "decrypt":
            return misc.get_char_set(data, cipher_obj.CHAR_SET, encrypt_or_decrypt == "encrypt")

    # Figure out the key to use during encryption/decryption
    def get_key() -> (str, str, str):
        """
        Figure out the correct key to use:
            "zero characters" is an encrypting cipher that doesn't need a key input
            "calculated characters" is a decrypting cipher that finds the key automatically
            "single character" is a symmetric encrypting/decrypting cipher that uses a single user-entered character
            "multiple characters" is an symmetric encrypting/decrypting cipher that uses user-entered multiple characters
            "multiple generated characters" is a symmetric encrypting/decrypting cipher that uses randomly generated keys

        :return:                   (str) symmetric key, may or may not be filled
        :return:                   (str) public key, may or may not be filled
        :return:                   (str) private key, may or may not be filled
        """


        # This help function obtains a general key from the user and returns that
        @misc.static_vars(general_key="Random key")
        def get_general_key() -> str:
            """
            This function obtains a key of any length from the user

            :return: (str) the user-entered key
            """

            # In encrypt, blanks means to use the default key
            if encrypt_or_decrypt == "encrypt":
                # TAKE A KEY
                key = input("Enter a key (Leave empty to use the default key \"{}\"): "
                            .format(get_general_key.general_key))

                # IF THE USER DID NOT GIVE ANYTHING, then use the default key
                if key == "":
                    key = get_general_key.general_key

                return key

            # In decrypt, blanks means to try to use the automatic cipher if possible
            else:

                if cipher_module.find("unknown") != -1:             # Automatic cipher is used
                    return ""

                else:
                    # Blanks are not allowed
                    if encrypt_or_decrypt == "encrypt":             # Manual user-key entered cipher is used
                        # TAKE A KEY
                        key = input("Enter the key: ")

                        while key == "":
                            key = input("No key entered! Enter the key: ")


                        return key

        # This helper function obtain a single char key from the user and returns that
        @misc.static_vars(single_char_key=get_general_key.general_key[0])
        def get_single_char_key() -> str:
            """
            This function obtains a key from the user that must be a single character

            :return: (str) the single character key
            """


            # In encrypt, can use a default key
            if encrypt_or_decrypt == "encrypt":
                # TAKE A KEY
                key = input("Enter a single-character key (Leave empty to use default key \"{}\"): "
                            .format(get_single_char_key.single_char_key))

                # While the key is not valid, ask user to enter a key again
                while True:

                    # If the user did not enter a key, use the default key
                    if key == "":
                        key = get_single_char_key.single_char_key

                    # IF THE USER DID NOT GIVE A SINGLE CHARACTER, FORCE THE USER TO ENTER IT AGAIN
                    if len(key) != 1:
                        key = input("Not a single character! Enter a single-character key "
                                    "(Leave empty to use default key \"{}\"): "
                            .format(get_single_char_key.single_char_key))
                        continue
                    # All checks passed, so break out of the for loop
                    break
                return key

            # In decrypt, try to use automatic cipher if possible
            else:

                # Try to use the automatic cipher
                if cipher_module.find("unknown") != -1:
                    return ""

                else:                                          # Else, user NEEDS to enter a key
                    # TAKE A KEY
                    key = input("Enter a single-character key: ")

                    # While the key is not valid, ask user to enter a key again
                    while True:

                        # If the user did not enter a key, ask for the key again
                        if key == "":
                            key = input("No key entered! Enter a single-character key: ")

                        # IF THE USER DID NOT GIVE A SINGLE CHARACTER, FORCE THE USER TO ENTER IT AGAIN
                        if len(key) != 1:
                            key = input("Not a single character! Enter a single-character key: ")
                            continue
                        # All checks passed, so break out of the for loop
                        break
                    return key

        # This helper function obtains a private key from the user
        def get_private_key() -> str:
            """
            This function obtains a key of any length fro the user

            :return: (str) the user-entered key
            """

            # TAKE A KEY
            key = input("Enter the private key: ")

            # While the key is not valid
            while True:

                # If nothing entered
                if key == "":
                    key = input("No key given! Enter the private key: ")
                    continue

                # All checks passed, so break out of loop
                break

            return key

        # This helper function gets a public key from the user. If the user wants to generate keys, then input() is blank
        def get_public_key() -> str:
            """
            This function obtains a public key from the user. If nothing entered, then the user wants to generate a key.

            :return: (str) the user-entered key
            """

            # Take a key
            key = input("Enter the public key (Leave empty to generate public/private keys): ")

            return key


        key         = ""
        public_key  = ""
        private_key = ""

        if cipher_obj.CIPHER_TYPE == "symmetric":
            if cipher_obj.KEY_TYPE         == "zero characters":
                key = ""

            elif cipher_obj.KEY_TYPE == "calculated characters" or cipher_obj.KEY_TYPE == "calculated character":
                key = ""

            elif cipher_obj.KEY_TYPE       == "single character":
                key = get_single_char_key()

            elif cipher_obj.KEY_TYPE       == "multiple characters":
                key = get_general_key()

            elif cipher_obj.KEY_TYPE       == "characters":
                if encrypt_or_decrypt   == "encrypt":                   # If encrypting, key is generated
                    key = ""
                elif encrypt_or_decrypt == "decrypt":
                    key = get_general_key()


        elif cipher_obj.CIPHER_TYPE == "asymmetric":
            if encrypt_or_decrypt == "encrypt":
                public_key = get_public_key()                           # get_public_key() will get the user to enter a
                                                                        # public key from some previous encryption or
                                                                        # blank. If blank, encrypt() functions in
                                                                        # Encryption will generate their own public and
                                                                        # private keys.
            elif encrypt_or_decrypt == "decrypt":
                private_key = get_private_key()  # Private keys are required, unlike public ones


        return key, public_key, private_key

    # Figure out the mode of operation to use during encryption/decryption (function handles non-block ciphers also)
    def get_mode_of_op() -> str:


        def get_symm_encryption_mode_of_encoding() -> str:
            """
            This gets a mode of encoding for encrypting. This means that the user can have a default mode of encoding

            :return: (str) The name of mode of encoding
            """
            # Print ouf the prompt for the user
            selection = input("Enter the mode of operation to be used (To use the default scheme, "
                              "\"cbc\", leave empty): ")

            # Loop while the user gives an invalid alphabet
            while True:

                if selection[0:4] == "info":
                    print("The available modes of operation are: ", end="")


                    for mode in Cipher.MODES_OF_OPERATION:
                        if mode == "ecb":
                            print(" " * (45 - len("The available modes of operation are: ")) + mode)

                        else:
                            print(" " * 45 + mode)


                    selection = input("\nEnter the mode of operation to be used for ciphertext (To use the default "
                                      "mode, \"ecb\", leave empty): ")
                    continue

                elif selection == "":
                    selection = "cbc"
                    break


                elif selection.rstrip() not in Cipher.MODES_OF_OPERATION:
                    selection = input("Invalid mode of operation (%s)! Try again: " % selection.rstrip())
                    continue

                # If here, then all clear
                else:
                    break

            return selection

        def get_symm_decryption_mode_of_encoding() -> str:
            """
            In decryption mode, get ta mode of encoding. This means no default modes

            :return:
            """
            # Print ouf the prompt for the user
            selection = input("Enter the mode of operation to be used: ")

            # Loop while the user gives an invalid alphabet
            while True:

                if selection[0:4] == "info":
                    print("The available modes of operation are: ", end="")

                    for mode in Cipher.MODES_OF_OPERATION:
                        if mode == "ecb":
                            print(" " * (45 - len("The available modes of operation are: ")) + mode)

                        else:
                            print(" " * 45 + mode)

                    selection = input("\nEnter the mode of operation to be used: ")
                    continue

                elif selection == "":
                    selection = input("\nNothing entered! Enter the mode of operation to be used: ")
                    break


                elif selection.rstrip() not in Cipher.MODES_OF_OPERATION:
                    selection = input("Invalid mode of operation (%s)! Try again: " % selection.rstrip())
                    continue

                # If here, then all clear
                else:
                    break

            return selection


        def get_asymm_encryption_mode_of_encoding() -> str:
            """
            This gets a mode of encoding for encrypting. This means that the user can have a default mode of encoding

            :return: (str) The name of mode of encoding
            """
            # Print ouf the prompt for the user
            selection = input("Enter the mode of operation to be used (To use the default mode, "
                              "\"cbc\", leave empty): ")

            # Loop while the user gives an invalid alphabet
            while True:

                if selection[0:4] == "info":
                    print("The available modes of operation are: ", end="")


                    for mode in Cipher.ASYMMETRIC_MODES_OF_OPERATION:
                        if mode == "ecb":
                            print(" " * (45 - len("The available modes of encryption are: ")) + mode)

                        else:
                            print(" " * 45 + mode)


                    selection = input("\nEnter the mode of encoding to be used for ciphertext (To use the default "
                                      "mode, \"ecb\", leave empty): ")
                    continue

                elif selection == "":
                    selection = "cbc"
                    break


                elif selection.rstrip() not in Cipher.ASYMMETRIC_MODES_OF_OPERATION:
                    selection = input("Invalid mode of operation (%s)! Try again: " % selection.rstrip())
                    continue

                # If here, then all clear
                else:
                    break

            return selection

        def get_asymm_decryption_mode_of_encoding() -> str:
            """
            In decryption mode, get ta mode of encoding. This means no default modes

            :return:
            """
            # Print ouf the prompt for the user
            selection = input("Enter the mode of operation to be used: ")

            # Loop while the user gives an invalid alphabet
            while True:

                if selection[0:4] == "info":
                    print("The available modes of operation are: ", end="")

                    for mode in Cipher.ASYMMETRIC_MODES_OF_OPERATION:
                        if mode == "ecb":
                            print(" " * (45 - len("The available modes of operation are: ")) + mode)

                        else:
                            print(" " * 45 + mode)

                    selection = input("\nEnter the mode of operation to be used: ")
                    continue

                elif selection == "":
                    selection = input("\nNothing entered! Enter the mode of operation to be used: ")
                    break


                elif selection.rstrip() not in Cipher.ASYMMETRIC_MODES_OF_OPERATION:
                    selection = input("Invalid mode of opeartion (%s)! Try again: " % selection.rstrip())
                    continue

                # If here, then all clear
                else:
                    break

            return selection





        # If doesn't use mode of operation, just exit function
        if cipher_obj.IS_BLOCK_CIPHER is False:
            return ""


        # If symmetric block cipher, then any mode of operation can be used
        if cipher_obj.CIPHER_TYPE == "symmetric":
            if encrypt_or_decrypt == "encrypt":
                return get_symm_encryption_mode_of_encoding()

            elif encrypt_or_decrypt == "decrypt":
                return get_symm_decryption_mode_of_encoding()

        elif cipher_obj.CIPHER_TYPE == "asymmetric":
            if encrypt_or_decrypt == "encrypt":
                return get_asymm_encryption_mode_of_encoding()

            elif encrypt_or_decrypt == "decrypt":
                return get_asymm_decryption_mode_of_encoding()

    # Figure out the block size to use (function handles non-variable block ciphers or non-block ciphers also)
    def get_block_size() -> int:
        """
        Gets block size for the encryption/decryption.

        :return: (int) The block size to use
        """

        def get_encryption_block_size() -> int:
            """
            This gets block size. This means that the user can have a default block size

            :return: (int) The block size to use
            """

            # Print ouf the prompt for the user
            selection = input("{}. (To use the default block size, \"{}\", "
                              "leave empty): "
                              .format(cipher_obj.PROMPT_BLOCK_SIZE, cipher_obj.DEFAULT_BLOCK_SIZE))

            # Loop while the user gives an invalid block size
            while True:

                # Use default block size.
                if selection == "":
                    selection = cipher_obj.DEFAULT_BLOCK_SIZE
                    break

                # If the user did not enter a number
                try:
                    selection = int(selection, 10)
                except:
                    selection = input("{} is not a number! {}. (To use the default "
                                      "block size, \"{}\", leave empty): "
                                      .format(selection, cipher_obj.PROMPT_BLOCK_SIZE, cipher_obj.DEFAULT_BLOCK_SIZE))
                    continue

                # Not a legitimate block size
                block_size = selection
                if eval(cipher_obj.EXPRESSION_BLOCK_SIZE) == False:
                    selection = input("{} is an invalid block size! {}. (To use the "
                                      "default block size, \"{}\", leave empty): "
                                      .format(selection, cipher_obj.PROMPT_BLOCK_SIZE,
                                              cipher_obj.DEFAULT_BLOCK_SIZE))
                    continue

                # If here, then all clear
                else:
                    break

            return selection

        def get_decryption_block_size() -> int:
            """
            In decryption mode, get block size. This means no default block sizes.

            :return: (int) The chosen block size
            """

            # Print ouf the prompt for the user
            selection = input("{}. Enter it: "
                              .format(cipher_obj.PROMPT_BLOCK_SIZE))

            # Loop while the user gives an invalid block size
            while True:

                # User entered nothing
                if selection == "":
                    selection = input("Nothing entered! {}: "
                                      .format(cipher_obj.PROMPT_BLOCK_SIZE))
                    break

                # If the user did not enter a number
                try:
                    selection = int(selection, 10)
                except:
                    selection = input("{} is not a number! E{}: "
                                      .format(selection, cipher_obj.PROMPT_BLOCK_SIZE))
                    continue

                # Not a legitimate block size
                block_size = selection
                if eval(cipher_obj.EXPRESSION_BLOCK_SIZE) is False:
                    selection = input("{} is an invalid block size! {}: "
                                      .format(selection, cipher_obj.PROMPT_BLOCK_SIZE))
                    continue

                # If here, then all clear
                else:
                    break

            return selection


        # If no variable block size, then just return default block size
        if cipher_obj.VARIABLE_BLOCK_SIZE is False:
            return cipher_obj.DEFAULT_BLOCK_SIZE

        elif encrypt_or_decrypt == "encrypt":
            return get_encryption_block_size()

        elif encrypt_or_decrypt == "decrypt":
            return get_decryption_block_size()

    # Figure out the key size to use (function handles non-variable block ciphers or non-block ciphers also)
    def get_key_size() -> int:
        """
        Gets key size for the encryption/decryption.

        :return: (int) The key size to use
        """

        def get_encryption_key_size() -> int:
            """
            This gets key size. This means that the user can have a default key size

            :return: (int) The key size to use
            """



            # Print out the prompt for the user
            selection = input("{}. (To use the default key size, \"{}\", "
                              "leave empty): "
                              .format(cipher_obj.PROMPT_KEY_SIZE, cipher_obj.DEFAULT_KEY_SIZE))

            # Loop while the user gives an invalid block size
            while True:

                # Use default block size.
                if selection == "":
                    selection = cipher_obj.DEFAULT_KEY_SIZE
                    break

                # If the user did not enter a number
                try:
                    selection = int(selection, 10)
                except:
                    selection = input("{} is not a number! {}. (To use the default "
                                      "key size, \"{}\", leave empty): "
                                      .format(selection, cipher_obj.PROMPT_KEY_SIZE, cipher_obj.DEFAULT_KEY_SIZE))
                    continue

                # Not a legitimate key size
                key_size = selection
                if eval(cipher_obj.EXPRESSION_KEY_SIZE) == False:
                    selection = input("{} is an invalid key size! {}. (To use the "
                                      "default key size, \"{}\", leave empty): "
                                      .format(selection, cipher_obj.PROMPT_KEY_SIZE, cipher_obj.DEFAULT_KEY_SIZE))
                    continue

                # If here, then all clear
                else:
                    break

            return selection

        def get_decryption_key_size() -> int:
            """
            In decryption mode, get key size. This means no default key sizes.

            :return: (int) The chosen key size
            """

            # Print out the prompt for the user
            selection = input("{}. Enter the key:"
                              .format(cipher_obj.PROMPT_KEY_SIZE))

            # Loop while the user gives an invalid block size
            while True:

                # User entered nothing
                if selection == "":
                    selection = input("Nothing entered! {}: "
                                      .format(cipher_obj.PROMPT_KEY_SIZE))
                    break

                # If the user did not enter a number
                try:
                    selection = int(selection, 10)
                except:
                    selection = input("{} is not a number! {}: "
                                      .format(selection, cipher_obj.PROMPT_KEY_SIZE))
                    continue

                # Not a legitimate key size
                key_size = selection
                if eval(cipher_obj.EXPRESSION_KEY_SIZE) == False:
                    selection = input("{} is an invalid key size! {}: "
                                      .format(selection, cipher_obj.PROMPT_KEY_SIZE))
                    continue

                # If here, then all clear
                else:
                    break

            return selection


        # If no variable key size, then just return default block size
        if cipher_obj.VARIABLE_KEY_SIZE is False:
            return cipher_obj.DEFAULT_KEY_SIZE

        # Else, take the key size
        elif encrypt_or_decrypt == "encrypt":
            return get_encryption_key_size()

        elif encrypt_or_decrypt == "decrypt":
            return get_decryption_key_size()

    # Write out the processed data
    def write_processed_data(output_location: str) -> None:
        with open(output_location, "w", encoding="utf-8") as output_file:
            output_file.write(processed_data)

    # Write out relevant info
    def write_info_file(info_location: str) -> None:

        info_file = open(info_location, "w", encoding="utf-8")

        # Holds name related to the process (either encryption or decryption)
        if encrypt_or_decrypt == "encrypt":
            process_noun = "𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍"
            processed_text = "ciphertext"
            process_verb = "Encrypted"
        else:
            process_noun = "𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍"
            processed_text = "plaintext"
            process_verb = "Decrypted"

        # Begin to generate the lines of text to store in the file. Start with the "title"
        lines = []
        lines.append("\n\n\n\n\n\n\n{}          with {}          on {}"
                     .format(process_noun, type(cipher_obj).CIPHER_NAME, cipher_obj.source_location))

        # Print out the symmetric_key/public_and_private_key
        if cipher_obj.CHAR_SET == "alphabet":                                 # If not a block cipher
            lines.append("―――――――― key ――――――――")
            lines.append("{}".format(cipher_obj.key))
            lines.append("―" * 67)

        elif cipher_obj.CIPHER_TYPE == "symmetric":                           # Is a symmetric block cipher
            lines.append("―" * 67)
            lines.append("―――――――― {}-bit key ".format(cipher_obj.key_size).ljust(73, "―"))
            lines.append("{}".format(cipher_obj.key))
            lines.append(("――――――――"
                          + " {}(s) ".format(format(cipher_obj.encrypt_time_for_key,
                                                    ".20f")[0:len(str(cipher_obj.key_size)) + 5]))
                            .ljust(73, "―"))
            lines.append("―" * 67)

        # Print out the private key if is an asymmetric cipher
        if cipher_obj.CIPHER_TYPE == "asymmetric":                            # Is an asymmetric block cipher
            lines.append("―" * 67)
            lines.append("―――――――― {}-bit public key ".format(cipher_obj.key_size)).ljust(73, "―")
            lines.append("{}".format(cipher_obj.public_key))
            lines.append(("――――――――"
                          + " {}(s) ".format(format(cipher_obj.encrypt_time_for_key,
                                                    ".20f")[0:len(str(cipher_obj.key_size)) + 5]))
                            .ljust(73, "―"))
            lines.append("―" * 67)

        # Print out the alphabet/encoding_scheme
        lines.append("The {}'s {} is: \"{}\"".format(processed_text, cipher_obj.CHAR_SET, char_set))

        # Print out the total time of encryption/decryption
        if cipher_obj.CHAR_SET == "alphabet":  # "alphabet" indicates non-block cipher
            lines.append("{} in these seconds: {}(s) with {} characters"
                         .format(process_verb, format(time_for_algorithm, ".12f")[0:14],
                                 "{:,}".format(len(cipher_obj.plaintext))))
        else:
            lines.append("{} in these seconds: {}(s) with {} characters"
                         .format(process_verb,
                                 format(time_for_algorithm, ".12f")[0:14],
                                 "{:,}".format(len(cipher_obj.plaintext)),
                                 "{:,}".format(cipher_obj.num_blocks)))
            lines.append(" " * 55 + "and {} blocks ({} characters each)"
                         .format("{:,}".format(cipher_obj.num_blocks),
                                 "{:,}".format(round(len(cipher_obj.plaintext) / cipher_obj.num_blocks, 2))))

        # Figure out the microseconds per character
        lines.append("Microseconds per character: {}(µs)"
                     .format(format(cipher_obj.encrypt_time_for_algorithm / len(cipher_obj.plaintext) * 1000000,
                                    ".12f")))

        # Concatenate all the strings, with a new line character between them. Then, write to file
        misc.format_to_colon(lines)
        all_lines = "\n".join(lines)
        info_file.write(all_lines)
        info_file.close()




    # Get parameters needed to actually create the Cipher object
    plaintext, ciphertext = set_plaintext_or_ciphertext()
    char_set = get_char_set()
    key, public_key, private_key = get_key()
    mode_of_op = get_mode_of_op()
    block_size = get_block_size()
    key_size   = get_key_size()


    # Create the actual Cipher object with the correct parameters
    cipher_obj = eval("{}.{}(plaintext, ciphertext, char_set, mode_of_op, key, public_key, private_key, "
                      "      block_size, key_size, source_location, output_location)"
                      .format(cipher_module, cipher_class_name))


    # Run the encryption/decryption and calculate time_for_algorithm. Also, print out the results
    if encrypt_or_decrypt == "encrypt":
        cipher_obj.encrypt_plaintext()                                  # Decorator saves time_overall and time_for_keys
        processed_data     = cipher_obj.ciphertext
        time_overall       = cipher_obj.encrypt_time_overall
        time_for_keys      = cipher_obj.encrypt_time_for_key
        time_for_algorithm = cipher_obj.encrypt_time_for_algorithm
        print("*" * 120 + "\n\nThis is the RESULTING CIPHERTEXT: \n{}".format(processed_data))
    else:
        cipher_obj.decrypt_ciphertext()
        processed_data     = cipher_obj.plaintext
        time_overall       = cipher_obj.decrypt_time_overall
        time_for_keys      = cipher_obj.decrypt_time_for_key
        time_for_algorithm = cipher_obj.decrypt_time_for_algorithm
        print("*" * 120 + "\n\nThis is the RESULTING PLAINTEXT: \n{}".format(processed_data))


    # Write out the output to the output_location
    write_processed_data(output_location)




    # Write out the info in the info file (path is output_location appended with "_(Relevant_Information)")
    write_info_file(output_location + "_(Relevant_Information)")















# Print out available Encryption/Decryption types
def _usage() -> None:

    print("***********************************************************************************************************")
    print("See README for usage."
        + "\nTo print out the available cipher types, type \"help\".")
    print()

    print("ENCRYPTION/DECRYPTION TYPES AVAILABLE: ")
    print("Available for both encryption and decryption: ", end = "")
    print(*(Cipher.ENCRYPTION_SET & Cipher.DECRYPTION_SET), sep=", ")
    print("Available for decryption only: ", end = "")
    print(*(Cipher.DECRYPTION_SET - Cipher.ENCRYPTION_SET), sep=", ")
    print()

# Parse user input and return relevant information
def _parse_user_input() -> (str, str, str, str, str):
    """
    This function parses user input and returns relevant information.
    User input is unix-like, with: command [optional flag] (argument) <optional argument>
        encrypt (cipher) (plaintext_file_path*)  <output_file_path>
        decrypt (cipher) (ciphertext_file_path*) <output_file_path>
        test    [optional flag] <cipher>
        help
        exit
        database [options flag] <encrypted_db_file_path*>

    * File paths with spaces in the name must be escaped with "\ ".
    So the path:     Resources/Library/Space File.txt
    is typed out as: Resources/Library/Space\ File.txt

    :return: cipher             (str) stores the cipher type that the user wants to use
    :return: encrypt_or_decrypt (str) Either "encrypt" or "decrypt". Indicates encrypt or decrypt mode
    :return: data               (str) the information to be encrypted/decrypted
    :return: source_location    (str) The filepath to the source file of the text
    :return: output_location    (str) the output location of the generated file
    """

    # Variables to return
    cipher             = "" # The name of the cipher to use
    encrypt_or_decrypt = "" # Either "encrypt" or "decrypt". Indicates which mode to use
    data               = "" # The string of the input. Either plaintext or ciphertext
    source_location    = "" # The file path of the source file of the text
    output_location    = "" # The file path to store the output of encryption/decryption





    statement = input("Enter statement: ")                # Obtain the user input


    # Return only when the statements are "encrypt" or "decrypt". Otherwise, keep looping when handling other commands.
    while True:


        # Read command (the first word)
        if statement.find(" ") != -1:                                      # If multiple words
            command = statement[0 : statement.find(" ")]
        else:
            command = statement                                            # Else, statement is the word



        if command == "help":
            # region Handle command: help
            _usage()                                                     # Print helpful info
            statement = input("Enter statement: ")                      # Obtain user input for next iteration
            continue                                                    # Jump to next iteration
            # endregion



        if command == "clear":
            # region Handle command: clear


            # delete files in /Files_Decrypted and Files_Encrypted
            for file in os.listdir("Resources/Files_Decrypted"):
                    os.unlink("Resources/Files_Decrypted/" + file)
            for file in os.listdir("Resources/Files_Encrypted"):
                    os.unlink("Resources/Files_Encrypted/" + file)


            # If -a flag, then ask for confirmation
            statement = statement.split(" ")                            # Split statement into words separated by spaces
            if len(statement) > 1 and statement[1] == "-a":
                confirmation = input("Confirm deletion of Databases, Files_Decrypted, Files_Encrypted, "
                                     + "and Files_Logs (type \"y\"): ")
                if confirmation == "y":
                    for file in os.listdir("Resources/Databases"):
                        os.unlink("Resources/Databases/" + file)
                    for file in os.listdir("Resources/Files_Logs"):
                        os.unlink("Resources/Files_Logs/" + file)


            # Obtain next command
            statement = input("Files deleted. Enter statement: ")        # obtain user input
            continue
            # endregion



        if command == "exit":
            # region Handle command: exit
            print("Exiting program...")
            exit(0)
            # endregion



        if command == "test":
            # region Handle command: test

            prompt = ""                                                 # The prompt to return
            statement = statement.split(" ")                            # Split statement into words separated by spaces

            # There should only be two arguments total (the command + option) or (the command + optional_arg). If
            # there are more arguments than two, then return error
            if len(statement) > 2:
                extra_args = " ".join(statement)                        # List to string
                extra_args = extra_args[extra_args.find(" ",            # extra args is after second space
                                 extra_args.find(" ") + 1) + 1:]
                prompt = "Extra argument (" + extra_args + ") given! Enter another statement: "


            # If no optional arguments or flags provided, enter testing mode with no cipher provided
            elif len(statement) == 1:
                test.manual_testing("")
                prompt = "Manual testing done! Enter another statement: "



            # Read for the "-a" flag for automated testing
            elif statement[1] == "-a":
                test.automated_testing()
                prompt = "Automated testing done! Enter another statement: "


            # If a Decryption cipher is provided, enter manual testing and run the test on that cipher
            else:
                test.manual_testing(statement[1])
                prompt = "Manual testing done! Enter another statement: "


            statement = input(prompt)                                   # Obtain user input for next iteration
            continue                                                    # Jump to the next iteration
            # endregion




        if command == "encrypt" or command == "decrypt":
            # region Handle command: encrypt or decrypt

            # Set encrypt_or_decrypt based on command encrypt/decrypt
            if command == "decrypt":
                encrypt_or_decrypt = "decrypt"
            elif command == "encrypt":
                encrypt_or_decrypt= "encrypt"

            # Function to split statement into list separated by spaces. (file_paths may have spaces escaped with "\ ")
            def statement_to_list(statement):
                """
                This splits a string at every space not escaped. Elements are stored into a list

                :param   (string) the string to split
                :return: (list) the split string
                """

                list_to_return = []                            # Construct the list here


                # Loop through the statement, and split when space is occurred. Ignore escaped's spaces ("\ ")
                while statement != "":

                    unescaped_space_index = -1

                    # Loop until an unescaped space is found
                    while True:

                        unescaped_space_index = statement.find(" ", unescaped_space_index + 1)    # Find space index

                        if unescaped_space_index == -1:                                           # If no more spaces
                            list_to_return.append(statement)
                            statement = ""
                            break

                        if statement[unescaped_space_index - 1] == "\\":                          # If escaped, continue
                            continue
                        else:                                                                     # Else, space found
                            break

                    # If statement is empty, just break
                    if statement == "":
                        break

                    # Replace all escaped spaces up to the unescaped_space_index with just a space
                    list_element = statement[0:unescaped_space_index]
                    list_element = list_element.replace("\ ", " ")

                    # Save the segment up to the space and cut out from var statement
                    list_to_return.append(list_element)
                    statement = statement[unescaped_space_index + 1:]

                return list_to_return
            statement_list = statement_to_list(statement)

            # If too many arguments given (>3), then print error, and jump to the next iteration
            if len(statement_list) > 1 + 3:
                statement = input("Too many arguments (more than 3) were given! Enter another statement:")
                continue


            # Read the FIRST argument (index 1), and check that it is a legitimate encrypt/decrypt cipher. If not a
            # legitimate cipher, then print error and get the user to enter another command.
            cipher = statement_list[1]
            if not ((command == "encrypt" and cipher in Cipher.ENCRYPTION_SET)
                       or (command == "decrypt" and cipher in Cipher.DECRYPTION_SET)):     # If not legitimate cipher
                statement = input("Cipher (" + cipher + ") not recognized as "
                                  + ("an" if command == "encrypt" else "a")
                                  + " "
                                  + command
                                  + "ion cipher! Enter another statement: ")
                continue



            # Read the SECOND argument (source file path). Get data from source. If there is a failure, then print
            # error and get the user to enter another command
            input_path = statement_list[2]


            # If the input is "last", then use the data from the file path "pointed" to by last
            if input_path == "last":

                # Save the source location
                source_location = last

                #  open the file and store its contents in the string data.
                try:
                    my_file = open(last, "r", encoding="utf-8")
                    data = my_file.read()
                    my_file.close()
                except IOError:
                    statement = input("There is no last file! Try again: ")
                    continue
            # Otherwise, a source is given (NOT last)
            elif not input_path == "last":

                # Save the source location
                source_location = input_path

                #  Try to open the file as is (the literal file path)
                try:
                    source_location = input_path
                    my_file = open(input_path, "r", encoding="utf-8")
                    data = my_file.read()
                    my_file.close()

                except IOError:  # Search within Resources/Library, Resources/Files_Encrypted...
                    try:                                                              # Search Resources/Library
                        source_location = "./Resources/Library/" + input_path
                        my_file = open("Resources/Library/"
                                       + input_path, "r", encoding="utf-8")
                        data = my_file.read()
                        my_file.close()

                    except IOError:
                        try:                                                          # Search Resources/Files_Encrypted
                            source_location = "./Resources/Files_Encrypted/" + input_path
                            my_file = open("Resources/Files_Encrypted/"
                                           + input_path, "r", encoding="utf-8")
                            data = my_file.read()
                            my_file.close()

                        except IOError:
                            try:                                                      # Search Resources/Files_Decrypted
                                source_location = "./Resources/Files_Decrypted/" + input_path
                                my_file = open("Resources/Files_Decrypted/"
                                               + input_path, "r", encoding="utf-8")
                                data = my_file.read()
                                my_file.close()

                            except IOError:                                           # File not found
                                # File could not be found, inform the user of the error
                                statement = input("No such file or directory! Try again: ")
                                continue


                # if the input was empty, return an error
                if len(data) == 0:
                    statement = input("There is no data to process in file("
                                      + input_path + ")! Try again: ")
                    continue


            # Read the THIRD argument (output file path if it exists)
            try: output_path = statement_list[3]
            except: pass

            # If an output filepath is given, use that. Check that it could be opened or if it already exists
            if len(statement_list) == 1 + 3:
                output_location = statement_list[3]

                # See if the file already exists
                try:                                                                   # See if file already exists
                    my_file = open(output_location, "r", encoding="utf-8")
                    data = my_file.read()
                    my_file.close()
                except IOError:
                    statement = input("File (" + output_location + ") already exists."
                                      + "If you do not want to overwrite, then enter another new statement."
                                      + "Otherwise, to overwrite, press \"Enter.\" Proceed: ")
                    if not statement == "":                                            # New statement
                        continue
                    elif statement == "":                                              # User wants to overwrite, skip
                        pass

                # See if the file is openable
                try:                                                                   # Try to open file
                    my_file = open(output_location, "w", encoding="utf-8")
                    data = my_file.read()
                    my_file.close()
                except Exception:
                    statement = input("File (" + output_location+ ") is not openable! Enter another statement: ")
                    continue
            # Output filepath not given. Use default format
            else:

                # Encrypt default format
                if command == "encrypt":                               # Encrypt's default format
                    now = datetime.datetime.now()                      # For the time and date
                    output_location = "Resources/Files_Encrypted/" + input_path + "__" + cipher + "_encrypted_" \
                                      + now.strftime("%Y-%m-%d_h%Hm%Ms%S")

                # Decrypt default format
                else:                                                  # Decrypt's default format
                    now = datetime.datetime.now()                      # For the time and date
                    output_location = "Resources/Files_Decrypted/" + input_path + "__" + cipher + "_decrypted_" \
                                      + now.strftime("%Y-%m-%d_h%Hm%Ms%S")


            # Return all relevant variables
            return cipher, encrypt_or_decrypt, data, source_location, output_location
            # endregion




        if command == "database":
            # region Handle command: database

            statement = statement.split(" ")                            # Split statement into words separated by spaces
            prompt = ""

            # If no flags, then print error and ask the user for another statement
            if len(statement) < 2:
                prompt = "The command \"database\" used without" \
                            + "any flags! Enter another statement: "

            # Handle flags that take no arguments
            elif statement[1] == "-c":                                 # Handle clear flag
                user_check = input("All files will be deleted from "
                                   + "Resources/Databases. To conf"
                                     "irm, type \"y\": ")
                if user_check == "y":
                    for file in os.listdir("Resources/Databases"):     # delete files in /Files_Decrypted
                        os.unlink("Resources/Databases/" + file)
                    prompt = "Database files deleted. Enter " \
                             + "another statement: "
                else:
                    prompt = "Database deletion aborted. Enter" \
                             + " another statement: "

            elif statement[1] == "-i":
                pass


            statement = input(prompt)                                  # Obtain user input for next iteration
            continue                                                   # Jump to next iteration
            # endregion




        # Command not recognized
        else:

            # Print out prompt
            statement = input("Command (" + command + ") not recognized! Enter another statement: ")
            continue

# Print data and the output location
def _print_data_and_location(data, output_location) -> None:

    print("\nTHIS IS THE DATA: \n" + data)
    print("***********************************************************************************************************")
    print("\nNEW FILE LOCATED HERE: " + output_location)
    print("TYPE \"info\" FOR MORE INFORMATION ON FURTHER PROMPTS.\n")








# Call the main function
if __name__ == "__main__":
    main()























