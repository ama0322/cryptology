import time    # for timing the encryption/decryption processes
import csv     # to convert ngram csv to a dictionary
import base64  # for several character encoding schemes
import random  # to generate random numbers
import secrets # to generate cryptographically secure numbers
import codecs  # For hex string to utf-8 encoding




################################################################################################### RESOURCES ##########

# Sets containing available options for encryption/decryption. Add to this.
ENCRYPTION_SET = {"blowfish", "rotation", "rsa", "vigenere", "vigenere_exponential",
                  "vigenere_multiplicative"}

DECRYPTION_SET = {"blowfish", "rotation", "rotation_nokey", "rsa", "vigenere", "vigenere_exponential",
                  "vigenere_multiplicative",}






# The characters used for more classical-type ciphers
ALPHABETS = ["unicode", "unicode_plane0", "ascii", "extended_ascii"]

# Encoding schemes (completely random bits to characters)
BINARY_TO_CHAR_ENCODING_SCHEMES = ["base16", "base32", "base64", "base85", "ascii", "extended_ascii", "base4096"]


# Dictionary with character sets to the number of characters in them
CHAR_SET_TO_SIZE = {
    "base16": 16,
    "base32": 32,
    "base64": 64,
    "base85": 85,
    "ascii": 128,
    "extended_ascii": 256,
    "base4096": 4096,
    "unicode": 1114112,
    "unicode_plane0": 65536
}

# Unprintable characters in unicode
SURROGATE_LOWER_BOUND  = 55296              # inclusive
SURROGATE_UPPER_BOUND  = 57343              # inclusive
SURROGATE_BOUND_LENGTH = 57343 - 55296 + 1  # equal to 2048






# The general code to run during testing for encryption statistics (simple symmetric)
GENERAL_ENCRYPTION_CODE =\
    r"""new_file.writelines([
                             "\n\n\n𝓔𝓝𝓒𝓡𝓨𝓟𝓣𝓘𝓞𝓝",
                             "\n--------------- 𝐊𝐄𝐘 ---------------\n" + encryption_key 
                                + "\n-----------------------------------------------------------" 
                                + "-------------------------",
                             "\n𝐓𝐇𝐄 𝐂𝐈𝐏𝐇𝐄𝐑𝐓𝐄𝐗𝐓'𝐒 𝐂𝐇𝐀𝐑𝐀𝐂𝐓𝐄𝐑 𝐒𝐄𝐓 𝐈𝐒: " + alphabet_of(ciphertext),
                             "\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐄𝐃 𝐈𝐍 𝐓𝐇𝐄𝐒𝐄 𝐒𝐄𝐂𝐎𝐍𝐃𝐒: " + str(encryption_time) + " (s) 𝐖𝐈𝐓𝐇 "
                                + "{:,}".format(len(plaintext)) + " 𝐂𝐇𝐀𝐑𝐀𝐂𝐓𝐄𝐑𝐒",                             
                             "\n𝐌𝐈𝐂𝐑𝐎𝐒𝐄𝐂𝐎𝐍𝐃𝐒 𝐏𝐄𝐑 𝐂𝐇𝐀𝐑𝐀𝐂𝐓𝐄𝐑: " + str((encryption_time / len(plaintext)) * 1000000)
                                + " (μs)"
                            ])
    """

# The general code to run during testing for decryption statistics (simple symmetric)
GENERAL_DECRYPTION_CODE =\
    r"""new_file.writelines([
                             "\n\n\n𝓓𝓔𝓒𝓡𝓨𝓟𝓣𝓘𝓞𝓝",
                             "\n𝐓𝐇𝐄 𝐏𝐋𝐀𝐈𝐍𝐓𝐄𝐗𝐓'𝐒 𝐂𝐇𝐀𝐑𝐀𝐂𝐓𝐄𝐑 𝐒𝐄𝐓 𝐈𝐒: " + alphabet_of(plaintext),
                             "\n𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐄𝐃 𝐈𝐍 𝐓𝐇𝐄𝐒𝐄 𝐒𝐄𝐂𝐎𝐍𝐃𝐒: " + str(decryption_time) + " (s) 𝐖𝐈𝐓𝐇 "
                                + "{:,}".format(len(plaintext)) + " 𝐂𝐇𝐀𝐑𝐀𝐂𝐓𝐄𝐑𝐒",
                             "\n𝐓𝐈𝐌𝐄𝐒 𝐋𝐎𝐍𝐆𝐄𝐑 𝐓𝐇𝐀𝐍 𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍: " + str(decryption_time/encryption_time) + " (times)",                 
                             "\n𝐌𝐈𝐂𝐑𝐎𝐒𝐄𝐂𝐎𝐍𝐃𝐒 𝐏𝐄𝐑 𝐂𝐇𝐀𝐑𝐀𝐂𝐓𝐄𝐑: " + str((decryption_time / len(plaintext)) * 1000000)
                                + " (μs)"
                            ])
    """


######################################################################### USER INTERFACING AND FUNCTION CALLS ##########



# This functions calls everything necessary in order to make the encryption/decryption. Once the
# encryption/decryption is finished, this function writes two files. One is the actual encryption/decryption result,
# and the other contains relevant information about the encryption/decryption (such as the key used or time taken)
def execute_encryption_or_decryption(data:str, output_location:str, package:str, module:str,
                                     encrypt_or_decrypt:str) -> None:
    """
    This function make all necessary calls, decrypts/encrypts, and info to the two files.

    :param data:              (str) the data to be encrypted or decrypted
    :param output_location:   (str) file path to store the output in
    :param package:           (str) the name of the package that hte module is located in
    :param module:            (str) the module whose algorithm is used
    :param encrypt_or_decrypt:(str) either "encrypt" or "decrypt"
    :return: None
    """
    char_set = ""                         # Is alphabet_size when using ALPHABETS. Otherwise, is name of encoding scheme
    key = ""                              # Fill the key here (if necessary)



    # Import the decryption version of module, and store the cipher information
    exec("from Cryptography.Decryption import " + module)
    char_set =    eval(module + ".char_set")
    cipher_type = eval(module + ".cipher_type")
    key_size =    eval(module + ".key_size")


    # Figure out the char_set to use, whether it be an alphabet, or an encoding scheme
    short_text = 300
    if char_set == ALPHABETS:                                                # If cipher uses ALPHABETS
        if encrypt_or_decrypt ==   "encrypt":                                # If encrypt mode, ask for alphabet
            char_set = CHAR_SET_TO_SIZE.get(_take_alphabet(ALPHABETS))       # char_set becomes the size of alphabet

        elif encrypt_or_decrypt == "decrypt":                                # Else decrypt, find alphabet
            if len(data) <= short_text:                                      # Short text, Ask user for alphabet
                char_set = _take_char_set_of_short_text(len(data),
                                                        ALPHABETS)
                char_set = CHAR_SET_TO_SIZE.get(char_set)
            else:                                                            # Find alphabet size automatically
                char_set = CHAR_SET_TO_SIZE.get(alphabet_of(data))

    elif char_set == BINARY_TO_CHAR_ENCODING_SCHEMES:                        # If cipher uses ENCODING SCHEMES
        if encrypt_or_decrypt ==   "encrypt":                                # If encrypt mode, ask for scheme
            char_set = _take_char_encoding_scheme(
                       BINARY_TO_CHAR_ENCODING_SCHEMES)

        elif encrypt_or_decrypt == "decrypt":                                # Else decrypt, find scheme
            if len(data) <= short_text:                                      # Short text, ask user for alphabet
                char_set = _take_char_set_of_short_text(len(data),
                                          BINARY_TO_CHAR_ENCODING_SCHEMES)
            else:                                                            # Find alphabet size automatically
                char_set = char_encoding_scheme_of(data)


    # FOR ENCRYPTION
    # Adjust the character set if necessary. Some ciphers cannot work correctly if the chosen ciphertext alphabet is
    # smaller than the plaintext's alphabet. They require at minimum the plaintext's alphabet to decrypt correctly.
    # So switch to use the plaintext's alphabet for encryption, and inform the user
    if encrypt_or_decrypt == "encrypt":                                 # Only "encrypt" mode needs adjusting
        try:                                                            # Non restricted ciphers fail "try" statement
            restrict = eval(module                                      # Ciphertext alphabet restricted
                        + ".ciphertext_alphabet_restricted")
            if restrict == True:                                        # Restrict by using plaintext's alphabet.
                alphabet = alphabet_of(data)
                if char_set < CHAR_SET_TO_SIZE.get(alphabet):           # If chosen alphabet (char_set) is insufficient
                    chosen_alphabet = next(alphabet for alphabet, size  # The selected alphabet.
                                           in CHAR_SET_TO_SIZE.items()
                                           if size == char_set)

                    print("The chosen alphabet for encryption ("
                        + chosen_alphabet + ") is"
                        + " insufficient for the alphabet that"
                        + " the plaintext is in."
                        + "\nTherefore, the alphabet for"
                        + " encryption is switched to: "
                        + alphabet)
                    char_set = CHAR_SET_TO_SIZE.get(alphabet)

        except Exception:                                               # Ciphertext alphabet not restricted. Do nothing
            pass




    # Figure out the correct key to use.
    # "zero characters" is an encrypting cipher that doesn't need a key input
    # "calculated characters" is a decrypting cipher that finds the key automatically
    # "single character" is a symmetric encrypting/decrypting cipher that uses a single user-entered character
    # "multiple characters" is an symmetric encrypting/decrypting cipher that uses user-entered multiple characters
    # "multiple generated characters" is a symmetric encrypting/decrypting cipher that uses randomly generated keys
    if cipher_type == "symmetric":
        if key_size     ==     "zero characters":
            key = ""

        elif key_size[0:20] == "calculated characters":
            key = ""

        elif key_size    ==    "single character":
            key = _get_single_char_key()

        elif key_size    ==    "multiple characters":
            key = _get_general_key()

        elif key_size    ==    "multiple generated characters":
            if encrypt_or_decrypt ==   "encrypt":                      # If encrypting, key is generated
                key = ""
            elif encrypt_or_decrypt == "decrypt":
                key = _get_general_key()


    elif cipher_type == "asymmetric":
        if encrypt_or_decrypt ==   "encrypt":
            key = _get_public_key()                                    # _get_public_key() will get the user to enter a
                                                                       # public key from some previous encryption or
                                                                       # blank. If blank, encrypt() functions in
                                                                       # Encryption will generate their own public and
                                                                       # private keys.
        elif encrypt_or_decrypt == "decrypt":
            key = _get_private_key()                                   # Private keys are required, unlike public ones


    # Everything gathered, now call the encrypt() or decrypt() function. Also, time it
    start_time = time.time()
    exec("from Cryptography." + package + " import " + module)                         # import correctly
    output = eval(module + "." + encrypt_or_decrypt + "(data, key, char_set)")         # algorithm call
    elapsed_time = time.time() - start_time


    # Open a new file to store the relevant information.
    info_file = open(output_location + "_(Relevant information)", "w", encoding="utf-8")
    exec("from Cryptography.Decryption" + " import " + module)            # Open up Decryption's cipher for cipher info


    # Print out relevant information for the encryption/decryption. At this point, output may be a tuple.
    if type(output) is str:                                # If str, then is a symmetric cipher with USER-ENTERED keys
        if encrypt_or_decrypt == "encrypt":                # Handle for straightforward symmetric encryption
            info_file.writelines([
                "\n\n\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                "\n--------------- key ---------------\n" + key
                    + "\n------------------------------------------------------------------------------------",
                "\n𝐓𝐡𝐞 𝐜𝐢𝐩𝐡𝐞𝐫𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + alphabet_of(output),
                "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(elapsed_time)
                    + " seconds with " + "{:,}".format(len(data)) + " characters.",
                "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str(
                    (elapsed_time / len(data)) * 1000000)
            ])
        elif encrypt_or_decrypt == "decrypt":              # Handle for straightforward symmetric decryption
            info_file.writelines([
                "\n\n\n𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                "\n--------------- key ---------------\n" + key
                    + "\n------------------------------------------------------------------------------------",
                "\n𝐓𝐡𝐞 𝐩𝐥𝐚𝐢𝐧𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + alphabet_of(output),
                "\n𝐃𝐞𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(elapsed_time)
                    + " seconds with " + "{:,}".format(len(output)) + " characters.",
                "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str(
                    (elapsed_time / len(output)) * 1000000)
            ])

    elif len(output) == 2:                                 # If len 2, then is a symmetric cipher with GENERATED keys
        if char_set in ALPHABETS:                          # Uses ALPHABETS
            if encrypt_or_decrypt == "encrypt":
                info_file.writelines([
                    "\n\n\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                    "\n--------------- generated key ---------------\n" + output[1] +
                    "\n------------------------------------------------------------------------------------",
                    "\n𝐓𝐡𝐞 𝐜𝐢𝐩𝐡𝐞𝐫𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + alphabet_of(output[0]),
                    "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(elapsed_time)
                        + " seconds with " + "{:,}".format(len(data)) + " characters.",
                    "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str(
                        (elapsed_time / len(data)) * 1000000)
                ])
            elif encrypt_or_decrypt == "decrypt":
                info_file.writelines([
                    "\n\n\n𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                    "\n--------------- key "
                        + str(eval( module + ".key_bits")) + "-bit ---------------\n"
                        + output[1]
                        + "\n------------------------------------------------------------------------------------",
                    "\n𝐓𝐡𝐞 𝐩𝐥𝐚𝐢𝐧𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + alphabet_of(output[0]),
                    "\n𝐃𝐞𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(elapsed_time)
                        + " seconds with " + "{:,}".format(len(output)) + " characters.",
                    "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str(
                        (elapsed_time / len(output)) * 1000000)
                ])
        elif char_set in BINARY_TO_CHAR_ENCODING_SCHEMES:              # If uses ENCODING SCHEMES
            if encrypt_or_decrypt == "encrypt":
                info_file.writelines([
                    "\n\n\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                    "\n--------------- generated key ---------------\n" + output[1] +
                    "\n------------------------------------------------------------------------------------",
                    "\n𝐓𝐡𝐞 𝐜𝐢𝐩𝐡𝐞𝐫𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + char_encoding_scheme_of(output[0]),
                    "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(elapsed_time)
                        + " seconds with " + "{:,}".format(len(data)) + " characters.",
                    "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str(
                        (elapsed_time / len(data)) * 1000000)
                ])
            elif encrypt_or_decrypt == "decrypt":
                info_file.writelines([
                    "\n\n\n𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                    "\n--------------- key " + str(
                        eval( module + ".key_bits")) + "-bit ---------------\n"
                        + output[1]
                        + "\n------------------------------------------------------------------------------------",
                    "\n𝐓𝐡𝐞 𝐩𝐥𝐚𝐢𝐧𝐭𝐞𝐱𝐭'𝐬 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫 𝐬𝐞𝐭 𝐢𝐬: " + alphabet_of(output[0]),
                    "\n𝐃𝐞𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(elapsed_time)
                        + " seconds with " + "{:,}".format(len(output)) + " characters.",
                    "\n𝐌𝐢𝐜𝐫𝐨𝐬𝐞𝐜𝐨𝐧𝐝𝐬 𝐩𝐞𝐫 𝐜𝐡𝐚𝐫𝐚𝐜𝐭𝐞𝐫: " + str(
                        (elapsed_time / len(output)) * 1000000)
                ])


    elif len(output) == 3:                                  # If len 3, then is an asymm. cipher with GEN'D or USER keys
        if encrypt_or_decrypt == "encrypt":
            if key == "":                                   # If user did not enter key, public and private are created
                info_file.writelines([
                    "\n\n\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                    "\n--------------- public key " +
                    str(eval( module + ".key_bits")) + "-bit ---------------\n"
                        + output[1]
                        + "\n------------------------------------------------------------------------------------",
                    "\n--------------- private key "
                        + str(eval( module + ".key_bits")) + "-bit ---------------\n"
                        + output[2]
                        + "\n------------------------------------------------------------------------------------",
                    "\n𝐓𝐡𝐞 𝐜𝐢𝐩𝐡𝐞𝐫𝐭𝐞𝐱𝐭'𝐬 𝐞𝐧𝐜𝐨𝐝𝐢𝐧𝐠 𝐬𝐜𝐡𝐞𝐦𝐞 𝐢𝐬: " + char_encoding_scheme_of(output[0]),
                    "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(elapsed_time)
                        + " seconds with " + "{:,}".format(len(data)) + " characters."
                ])
            elif key != "":                                 # If user gave public key. Print that out.
                info_file.writelines([
                    "\n\n\n𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                    "\n--------------- public key "
                        + str(eval( module + ".key_bits")) + "-bit ---------------\n"
                        + output[1]
                        + "\n------------------------------------------------------------------------------------",
                    "\n𝐓𝐡𝐞 𝐜𝐢𝐩𝐡𝐞𝐫𝐭𝐞𝐱𝐭'𝐬 𝐞𝐧𝐜𝐨𝐝𝐢𝐧𝐠 𝐬𝐜𝐡𝐞𝐦𝐞 𝐢𝐬: " + char_encoding_scheme_of(output[0]),
                    "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(elapsed_time)
                        + " seconds with " + "{:,}".format(len(data)) + " characters."
                ])
        elif encrypt_or_decrypt == "decrypt":                 # Print out the private key used to decrypt
            info_file.writelines([
                "\n\n\n𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍",
                "\n--------------- private key "
                    + str(eval( module + ".key_bits")) + "-bit ---------------\n"
                    + output[2]
                    + "\n------------------------------------------------------------------------------------",
                "\n𝐓𝐡𝐞 𝐜𝐢𝐩𝐡𝐞𝐫𝐭𝐞𝐱𝐭'𝐬 𝐞𝐧𝐜𝐨𝐝𝐢𝐧𝐠 𝐬𝐜𝐡𝐞𝐦𝐞 𝐢𝐬: " + char_encoding_scheme_of(output[0]),
                "\n𝐄𝐧𝐜𝐫𝐲𝐩𝐭𝐞𝐝 𝐢𝐧: " + str(elapsed_time)
                    + " seconds with " + "{:,}".format(len(data)) + " characters."
            ])

    # Now print out the ciphertext/plaintext in the proper file
    info_file.close()                                         # Close the relevant info file
    output_file = open(output_location, "w", encoding="utf-8")
    if type(output) is tuple: output = output[0]              # If output is a tuple, just want the text output
    output_file.write(output)
    output_file.close()

    # Print out to console the output
    print("*******************************************************")
    print("\nTHIS IS THE OUTPUT:\n" + output)








# This function runs encryption and decryption and writes statistics about the process
def testing_execute_encryption_and_decryption(encryption:str, decryption:str,
                                           plaintext:str, plaintext_source:str, encryption_key:str, char_set:str or int,
                                           output_location:str,
                                           cipher_name:str,
                                           encryption_code:str, decryption_code:str) -> None:
    """
    This function runs encryption and decryption and writes statistics about the process

    :param   encryption:       (str)        the name of the encryption cipher to use
    :param   decryption:       (str)        the name of the decryption cipher to use
    :param   plaintext:        (str)        the plaintext to perform encryption on
    :param   plaintext_source: (str)        the location where the plaintext is found
    :param   encryption_key:   (str)        the key to encrypt with
    :param   char_set:         (str or int) either the encoding scheme or the size of the alphabet used
    :param   output_location:  (str)        the file to write statistics into this
    :param   cipher_name:      (str)        the formal name of the cipher that is used
    :param   encryption_code:  (str)        the code to run that writes info about encryption
    :param   decryption_code:  (str)        the code to run that writes info about decryption
    :return: None
    """


    # RELEVANT INFO FOR ENCRYPTION/DECRYPTION
    ciphertext     = ""                                                # Build ciphertext here
    public_key     = ""                                                # May not be used
    private_key    = ""                                                # May not be used
    generated_key  = ""                                                # Symmetric generated keys. May not be used
    decryption_key = encryption_key                                    # The key used to decrypt. Symmetric by default


    # ADJUST THE CHARACTER SET IF NECESSARY. Some ciphers cannot work correctly if the chosen ciphertext alphabet is
    # smaller than the plaintext's alphabet. They require at minimum the plaintext's alphabet to decrypt correctly.
    # So switch to use the plaintext's alphabet for encryption, and inform the user
    exec("from Cryptography.Decryption import " + decryption)

    try:                                                                # Non restricted ciphers fail "try" statement
        restrict = eval(decryption                                      # Ciphertext alphabet restricted
                        + ".ciphertext_alphabet_restricted")
        if restrict == True:                                        # Restrict by using plaintext's alphabet.
            alphabet = alphabet_of(plaintext)
            if char_set < CHAR_SET_TO_SIZE.get(alphabet):           # If chosen alphabet (char_set) is insufficient

                chosen_alphabet = next(alphabet for alphabet, size  # The selected alphabet.
                                       in CHAR_SET_TO_SIZE.items()
                                       if size == char_set)
                print("The chosen alphabet for encryption ("
                        + chosen_alphabet + ") is"
                        + " insufficient for the alphabet that"
                        + " the plaintext is in."
                        + "\nTherefore, the alphabet for"
                        + " encryption is switched to: "
                        + alphabet)
                char_set = CHAR_SET_TO_SIZE.get(alphabet)

    except Exception:                                               # Ciphertext alphabet not restricted. Do nothing
        pass

    # EXECUTE THE ENCRYPTION, and store the output
    start_time = time.time()
    exec("from Cryptography.Encryption import " + encryption)          # Import module for encryption
    encryption_output = eval(encryption + ".encrypt(plaintext, "       # Run the encryption
                                                 + "encryption_key, "
                                                 + "char_set)")
    encryption_time = time.time() - start_time

    # STORE THE ENCRYPTION'S OUTPUT
    if type(encryption_output) is tuple:                               # If tuple, then ciphertext is in 1st index
        ciphertext = encryption_output[0]

        if len(encryption_output) == 3:                                # Len 3 indicates asymmetric keys generated
            public_key = encryption_output[1]
            private_key = encryption_output[2]
            decryption_key = private_key

        elif len(encryption_output) == 2:                              # Len 2 indicates symmetric key generated
            generated_key = encryption_output[1]
            decryption_key = generated_key
    else:                                                              # Not tuple, just regular ciphertext output
        ciphertext = encryption_output



    # RUN DECRYPTION, save time and decrypted text
    decrypted = ""
    start_time = time.time()
    exec("from Cryptography.Decryption import " + decryption)          # Import module for decryption
    decryption_output = eval(decryption + ".decrypt(ciphertext, "      # Run the actual decryption
                                                + "decryption_key, "
                                                + "char_set)")
    decryption_time = time.time() - start_time

    # Store the decryption's output
    if type(decryption_output) is tuple:                               # If tuple, then decrypted is in the first index
        decrypted = decryption_output[0]
    else:                                                              # Otherwise, decrypted is the only output
        decrypted = decryption_output



    # OPEN FILE FOR WRITING, and set up a space for personal notes
    new_file = open(output_location, "w", encoding="utf-8")
    if decrypted == plaintext:
        new_file.writelines([cipher_name + " on " + plaintext_source + "\nCORRECT \nNotes: "])
        print(cipher_name + "\u001b[32m" + ": 𝐂𝐎𝐑𝐑𝐄𝐂𝐓\n" + "\u001b[0m")
    else:
        new_file.writelines([cipher_name + " on " + plaintext_source + "\nINCORRECT \t\t\t\t\t"
                             + "Characters different: " + str(sum(1 for a, b in zip(plaintext, decrypted) if a != b))
                             + "\t Percent different: " + str((sum(1 for a, b in zip(plaintext, decrypted) if a != b) /
                                                             len(plaintext) * 100))
                             + "\nNotes: "])
        print(cipher_name + "\u001b[31m" + ": 𝐈𝐍𝐂𝐎𝐑𝐑𝐄𝐂𝐓\n" + "\u001b[0m")


    # Write out encryption information/statistics. Then, do the decryption information
    exec(encryption_code)
    exec(decryption_code)

    # Print out the ciphertext, decrypted text, and then the plaintext. Then, close fil
    new_file.writelines(["\n\n\nCiphertext: \n"     + ciphertext])
    new_file.writelines(["\n\n\nDecrypted text: \n" + decrypted])
    new_file.writelines(["\n\n\nPlaintext: \n"      + plaintext])
    new_file.close()












########################################################################################### USEFUL ALGORITHMS ##########

########## CHARACTER SET DETERMINATION ##########
# This function figures out what character set the encrypted data is in. More reliable on longer texts
def alphabet_of(ciphertext:str) -> str:
    """
    This function iterates through all the characters in the ciphertext and checks what sort of character set they are
    in. Note that this does not 100% guarantee that the plaintext was encrypted using this particular character
    set. More accurate for longer ciphertexts.

    :param ciphertext: (str) the ciphertext
    :return:           (str) the character set the ciphertext was most likely encrypted in
    """

    # first pass through ciphertext, check if there are unicode characters (65536 and above)
    for x in ciphertext:
        if ord(x) >= 65536:
            return "unicode"

    # seocnd pass through ciphertext, check if there are unicode_plane0
    for x in ciphertext:
        if ord(x) >= 256:
            return "unicode_plane0"

    # third pass through ciphertext, check if there are extended_ascii characters(128 and above)
    for x in ciphertext:
        if ord(x) >= 128:
            return "extended_ascii"

    # Otherwise, only ascii characters
        return "ascii"


# This function determine which character encoding scheme the encrypted data is in. More reliable on longer texts
def char_encoding_scheme_of(text:str) -> str:
    """
    This figures out which character encoding scheme was used on this text

    :param text: (str) the result of a character encoding scheme
    :return:     (str) the name of the character encoding scheme used
    """

    # If characters only in base16 char_set, return "base16"
    if all(character in "0123456789ABCDEF" for character in text):
        return "base16"

    # Test base32 char_set
    if all(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for character in text):
        return "base32"

    # Test base64 char_set
    if all(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for character in text):
        return "base64"

    # Test base85 char_set
    if all(character in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
                        for character in text):
        return "base85"

    # Test extended_ascii char_set
    if all( 0 <= ord(character) <256 for character in text):
        return "extended_ascii"

    # Else, is in base4096
    if all( 0 <= ord(character) <4096 for character in text):
        return "base4096"



########## TEXT/CHAR ENCODING SCHEMES ##########
# This function converts the ciphertext in integer form into the proper character encoding scheme . Pads up to keysize
def int_to_chars_encoding_scheme_pad(number:int, encoding:str, key_size:int) -> str:
    """
    This function turns an integer into a character using whichever chosen encoding scheme. This uses a bunch of if
    statements to build up the encoded string declared in the beginning. It is returned all the way in the end.

    :param number:   (int) the number to encode
    :param encoding: (str) the type of character encoding to use (see dict BINARY_TO_CHAR_ENCODING_SCHEMES)
    :param key_size: (int) The size of the key in bits (and thus, the ciphertext). Pad 0's in front if necessary.
                              This should be divisible by 8.
    :return:         (str) the encoded form.
    """

    # Build up encoded string here. Return at end of function.
    encoded = ""


    # If base16,
    if encoding == "base16":
        # Turn the number into a bytearray(Calculate bytes needed with key_size / 8)
        number = number.to_bytes( key_size // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b16encode(number))[2: -1]

    # If base32
    elif encoding == "base32":
        # Turn the number into a bytearray(Calculate bytes needed with key_size / 8)
        number = number.to_bytes( key_size // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b32encode(number))[2: -1]

    # If base 64
    elif encoding == "base64":

        # Turn the number into a bytearray(Calculate bytes needed with key_size / 8)
        number = number.to_bytes( key_size // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b64encode(number))[2: -1]


    # If base 85
    elif encoding == "base85":

        # Turn the number into a bytearray(Calculate bytes needed with key_size / 8)
        number = number.to_bytes( key_size // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b85encode(number))[2: -1]



    # If extended_ascii, turn int to bits. Read bits 8 at a time. Pad "0" in front if necessary
    elif encoding == "extended_ascii":

        # Turn the integer into a string with binary representation. Get rid of leading "0b"
        number = bin(number)[2:]

        # Pad the front if necessary (all the way up to key_size)
        if len(number) < key_size:
            number = (key_size - len(number)) * "0" + number

        # Read bits 8 at a time. Interpret those 8 bits as extended_ascii(unicode) and add to encoded
        while number != "":
            encoded += chr( int(number[0:8], 2) )
            number = number[8:]

    # If base4096, read 12 bits at a time. Interpret tham as unicode
    elif encoding == "base4096":

        # Turn the integer into a string with binary representation. Get rid of leading "0b"
        number = bin(number)[2:]

        # Pad the front if necessary (all the way up to key_size and divisible by 12)
        if len(number) < key_size:
            number = (key_size - len(number)) * "0" + number
        if len(number) % 12 != 0:
            number = (12 - (len(number) % 12)) * "0" + number

        # Read bits 12 at a time. Interpret those 12 bits as unicode and add to encoded.
        while number != "":
            encoded += chr( int(number[0:12], 2) )
            number = number[12:]




    return encoded


# This function converts an integer into chars with encoding scheme. DOES NOT pad up to anything
def int_to_chars_encoding_scheme(number:int, encoding:str) -> str:
    """
    This function turns an integer into a character using whichever chosen encoding scheme. This uses a bunch of if
    statements to build up the encoded string declared in the beginning. It is returned all the way in the end.

    :param number:   (int) the number to encode
    :param encoding: (str) the type of character encoding to use (see dict BINARY_TO_CHAR_ENCODING_SCHEMES)
    :return:         (str) the encoded form.
    """

    # Build up encoded string here. Return at end of function.
    encoded = ""

    # If base16,
    if encoding == "base16":
        # Turn the number into a bytearray(Pad up to the nearest byte)
        number = number.to_bytes( (number.bit_length() + 7) // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b16encode(number))[2: -1]

    # If base32
    elif encoding == "base32":
        # Turn the number into a bytearray(Pad up to nearest byte)
        number = number.to_bytes( (number.bit_length() + 7) // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b32encode(number))[2: -1]

    # If base 64
    elif encoding == "base64":

        # Turn the number into a bytearray(Pad up to nearest byte)
        number = number.to_bytes( (number.bit_length() + 7) // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b64encode(number))[2: -1]


    # If base 85
    elif encoding == "base85":

        # Turn the number into a bytearray(Pad up to nearest byte)
        number = number.to_bytes( (number.bit_length() + 7) // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b85encode(number))[2: -1]



    # If extended_ascii, turn int to bits. Read bits 8 at a time. Pad "0" in front if necessary
    elif encoding == "extended_ascii":

        # Turn the integer into a string with binary representation. Get rid of leading "0b"
        number = bin(number)[2:]

        # Pad the front if necessary (all the way up to nearest byte, so divisible by 8)
        if len(number) % 8 != 0:
            number = (8 - (len(number) % 8) ) * "0" + number

        # Read bits 8 at a time. Interpret those 8 bits as extended_ascii(unicode) and add to encoded
        while number != "":
            encoded += chr( int(number[0:8], 2) )
            number = number[8:]

    # If base4096, then read 12 bits at a time. Pad "0" in front if necessary
    elif encoding == "base4096":

        # Turn the integer into a string with binary representation. Get rid of leading "0b"
        number = bin(number)[2:]

        # Pad the front if necessary(make divisble by 12)
        if len(number) % 12 != 0:
            number = (12 - (len(number) % 12)) * "0" + number

        # Read bits 12 at a time. Interpret those 12 bits as unicode and add to encoded.
        while number != "":
            encoded += chr( int(number[0:12], 2) )
            number = number[12:]



    return encoded


# This function decodes characters into a number using the proper character encoding scheme
def chars_to_int_decoding_scheme(string:str, encoding:str) -> int:
    """
    Does the opposite of int_to_chars_encoding_scheme

    :param string:   (str) the string to be decoded
    :param encoding: (str) the name of the encoding scheme used
    :return:         (int) the decoded integer
    """

    decoded = 0


    # If scheme was hex, then use int()
    if encoding == "base16":
        string = string.encode()
        decoded = base64.b16decode(string)
        decoded = int.from_bytes(decoded, byteorder="big")

    # elif base32, use base64 module function. Then, turn the bytes into an integer
    elif encoding == "base32":
        string = string.encode()
        decoded = base64.b32decode(string)
        decoded = int.from_bytes(decoded, byteorder="big")

    # elif base64, use base64 module function. THen, turn bytes into an integer
    elif encoding == "base64":
        string = string.encode()
        decoded = base64.b64decode(string)
        decoded = int.from_bytes(decoded, byteorder="big")

    # elif base85, use base64 module's function. Then, turn bytes into an integer
    elif encoding == "base85":
        string = string.encode()
        decoded = base64.b85decode(string)
        decoded = int.from_bytes(decoded, byteorder="big")



    # elif extended_ascii, turn extended_ascii into a long string of bits. Then, read bits as an integer
    elif encoding == "extended_ascii":

        # Build up binary string here
        bin_string = ""

        # Loop through string. Add the extended_ascii characters one at a time to bin_string (in binary form).
        for x in string:

            # Obtain binary form of the extended_ascii character. Remove leading "0b"
            eight_bits = bin(ord(x))[2:]

            # Pad to eight digits if necessary
            if len(eight_bits) % 8 != 0:
                eight_bits = (8 - len(eight_bits) % 8) * "0" + eight_bits

            #Add to bin string
            bin_string += eight_bits


        # Read the binary string as an integer
        decoded = int(bin_string, 2)


    # elif base4096, turn base4096 into a long string of bits. Then, read bits as an integer
    elif encoding == "base4096":

        # Build up binary string here
        bin_string = ""

        # Loop through string. Add the extended_ascii characters one at a time to bin_string (in binary form).
        for x in string:

            # Obtain binary form of the base4096 character. Remove leading "0b"
            twelve_bits = bin(ord(x))[2:]

            # Pad to 8 digits if necessary
            if len(twelve_bits) % 12 != 0:
                twelve_bits = (12 - len(twelve_bits) % 12) * "0" + twelve_bits

            #Add to bin string
            bin_string += twelve_bits


        # Read the binary string as an integer
        decoded = int(bin_string, 2)



    return decoded


# This function encodes characters using whatever character encoding scheme
def chars_to_chars_encoding_scheme(string:str, encoding:str) -> str:
    """
    This encodes a string using chosen encoding scheme

    :param string:   (str) the string to encode
    :param encoding: (str) the name of the encoding scheme
    :return:         (str) the encoded result
    """

    encoded = ""

    if encoding == "base16":
        encoded = base64.b16encode(bytearray(string, "utf-8")).decode()

    elif encoding == "base32":
        encoded = base64.b32encode(bytearray(string, "utf-8")).decode()

    elif encoding == "base64":
        encoded = base64.b64encode(bytearray(string, "utf-8")).decode()

    elif encoding == "base85":
        encoded = base64.b85encode(bytearray(string, "utf-8")).decode()

    elif encoding == "extended_ascii":

        # Change string to hex format with utf-8
        hex = string.encode("utf-8").hex()


        # Read bytes (two hex digits) at a time. Interpret them as extended_ascii
        while hex != "":
            encoded += chr( int(hex[0: 2], 16) )
            hex = hex[ 2: ]

    elif encoding == "base4096":

        # Change string to hex format with utf-8
        hex = string.encode("utf-8").hex()

        # Pad string to be divisible by three if necessary
        if len(hex) % 3 != 0:
            hex = (3 - (len(hex) % 3)) * "0" + hex

        # Read bytes (three hex digits) at a time. Interpret them as base4096
        while hex != "":
            encoded += chr( int(hex[0: 3], 16) )
            hex = hex[ 3: ]


    return encoded


# This function decodes characters into a string using whatever character encoding scheme
def chars_to_chars_decoding_scheme(string:str, encoding:str) -> str:
    """
    This function decodes using the chosen encoding scheme.

    :param string:   (str) the decoded string
    :param encoding: (str) the name of the encoding method
    :return:         (str) the decoded string
    """

    decoded = ""

    if encoding == "base16":
        decoded = base64.b16decode(bytearray(string, "utf-8")).decode()

    elif encoding == "base32":
        decoded = base64.b32decode(bytearray(string, "utf-8")).decode()

    elif encoding == "base64":
        decoded = base64.b64decode(bytearray(string, "utf-8")).decode()

    elif encoding == "base85":
        decoded = base64.b85decode(bytearray(string, "utf-8")).decode()

    elif encoding == "extended_ascii":
        for char in string:
            # Convert each extended_ascii to bytes, then to a hex string. Concatenate
            decoded += (ord(char)).to_bytes(1, byteorder="big").hex()

        # Turn the bitstring into a regular string with utf-8 encoding
        decoded = codecs.decode(decoded, "hex").decode("utf-8") # Decode bytes to string using utf-8

    elif encoding == "base4096":
        for char in string:
            # Convert each base4096 to hex string of length 3. Concatenate
            hex_str = hex(ord(char))[2:] # remove leading "0x"
            if len(hex_str) % 3 != 0:
                hex_str = (3 - (len(hex_str) % 3)) * "0" + hex_str

            decoded += hex_str

        # pad hexstring to make even if necessary
        if len(decoded) % 2 != 0: decoded = "0" + decoded

        # Turn the hexstring into a regular string with utf-8 encoding
        decoded = codecs.decode(decoded, "hex").decode("utf-8") # Decode hex to string using utf-8
    return decoded




########## PRIME NUMBERS ##########


# This function returns a pair of primes whose product is of size key_bits
def get_prime_pair(key_bits:int) -> (int, int):
    """
    Figures out a pair of primes whose product is of size key_bits. When a prime is found, it is multiplied against
    all the primes in primes_list to try to find a pair that gives a correct size key. If one is not found,
    this prime is added to the list, and a new prime number is searched for.

    :param key_bits: (int) the bit length of the key (the product of the primes)
    :return:         (int) One prime number that is the factor of the key
    :return:         (int) Another prime number that is the factor of the key
    """

    # Create a static variable that counts the number of primes found
    get_prime_pair.primes_found = 0

    # the function to generate large primes. Pass in bit_length for the desired size of the generated prime
    def generate_prime(bit_length):
        """
        This function returns a large prime number of bit_length size. This works by producing a random number
        that is of size bit_length(in base 10). Then, the number is tested for primality. This is done by testing
        its compositeness with several small prime numbers to immediately rule out many composite numbers. If the
        number then passes that test, then the rabin-miller test is run up to 64 times to rule out composite. The
        returned number then has a very high probability that it is a prime number.

        :param bit_length: (int) the bit length of the generated prime
        :return: (int) the generated prime number
        """

        # This function checks if candidate is divisible by small primes. Return pass/fail and the prime that failed it
        def small_primes_primality_test(candidate):
            """
            This function uses the small primes test to test for primality.

            :param candidate: (the number to test for)
            :return: (boolean) indicating passed or failed test
            :return: (int) indicating the number that caused the failed test (0 if test passed)
            """
            small_primes = [
                2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
                103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
                223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337,
                347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
                463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
                607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
                743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881,
                883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021,
                1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129,
                1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
                1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
                1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
                1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621,
                1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759,
                1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901,
                1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029,
                2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153,
                2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297,
                2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417,
                2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579,
                2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699,
                2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819,
                2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963,
                2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119,
                3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259,
                3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391,
                3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539,
                3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671,
                3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803,
                3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929, 3931,
                3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091,
                4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231,
                4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373,
                4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519,
                4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663,
                4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813,
                4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969,
                4973, 4987, 4993, 4999
            ]

            # If 1 or less, not prime. Just return false
            if candidate <= 1:
                return False, 0

            # Check that number not evenly divisible by small primes
            for prime in small_primes:
                if candidate % prime == 0:
                    return False, prime

            # All the small primes have been checked, so the number passes the small primes test
            return True, 0

        # Test for primality using fermat's little theorem.
        def fermat_primality_test(candidate):

            # FERMAT"S LITTLE THEOREM: First, find 1 > i > number where number not divisible by i
            fermat_test_num = secrets.randbelow(candidate)
            while num_to_test % fermat_test_num == 0:
                fermat_test_num = secrets.randbelow(candidate)

            # Return test results
            return pow(fermat_test_num, candidate - 1, candidate) == 1

        # rabin-miller test
        def rabin_miller_primality_test(num, times_to_test):
            """
            Run rabin_miller tests times_to_test times. Return whether or not the number is a prime

            :param num: (int) number to test for primeness
            :param times_to_test: (int) the number of time to test rabin-miller
            :return: (boolean) indicates whether the number is prime
            """
            s = num - 1
            power = 0
            while s % 2 == 0:
                s = s // 2
                power += 1

            # Run the rabin miller test however many times
            trials = 0
            while trials < times_to_test:

                result = pow(random.randrange(2, num - 1), s, num)

                # Test does not apply for result == 1. Try again with a different base
                if result == 1:
                    continue

                # Check if the number is composite
                i = 0
                while result != (num - 1):

                    # At this point, the number is composite
                    if i == power - 1:
                        return False

                    # Not proven to be composite, so move to next iteration
                    else:
                        i = i + 1
                        result = (result ** 2) % num

                # Passed one rabin-miller test. Move onto the next one
                trials += 1

            # passed all tests, so probably prime
            return True

        # Set up static inner variable that counts the numbers of primes generated
        if not hasattr(generate_prime, "numbers_tested"): generate_prime.numbers_tested = 0

        # Loop until a prime number has been generated
        while True:

            # Generate a number that needs to be tested for primality
            num_to_test = secrets.randbits(bit_length)

            # Print updates and update
            print(str(generate_prime.numbers_tested) + " numbers tested for primality. Primes found: "
                  + str(get_prime_pair.primes_found))
            generate_prime.numbers_tested += 1

            # Set the lowest bit to 1 to make the number odd.
            num_to_test = num_to_test | 1

            # While small primes test fails, update number with += 2. Do until number no longer fits.
            test_result, failed_prime = small_primes_primality_test(num_to_test)
            while test_result == False and num_to_test.bit_length() == bit_length:
                # Print updates
                print(str(generate_prime.numbers_tested) + " numbers tested for primality. Primes found: "
                      + str(get_prime_pair.primes_found))
                generate_prime.numbers_tested += 1

                # Update the number, and run small primes test again
                num_to_test += 2
                test_result, failed_prime = small_primes_primality_test(num_to_test)

            # If the num_to_test is too big, then continue from the beginning
            if num_to_test.bit_length() != bit_length:
                continue

            # If failed the small_primes_primality_test, then generate new number
            if test_result == False:
                continue

            # If failed fermat's little theorem, then generate new number
            if fermat_primality_test(num_to_test) == False:
                continue

            # If the generated number was prime, then return
            if rabin_miller_primality_test(num_to_test, 64):
                return num_to_test

    # Tell generate_primes() to reset its numbers tested counter
    generate_prime.numbers_tested = 0

    # Create the list with one prime number is in it(primes are about half the size of key_bits)
    primes_list = [generate_prime(key_bits // 2)]; get_prime_pair.primes_found += 1

    # Loop until two prime numbers are found whose product is the correct size (key_bits)
    while True:

        # Generate a prime for testing
        prime_one = generate_prime(key_bits // 2); get_prime_pair.primes_found += 1


        # Test all pairs of primes for a key that is of proper size
        for prime_two in primes_list:

            # If the primes work out to make a key of correct size
            if (prime_one * prime_two).bit_length() == key_bits:

                # Print updates
                print(str(generate_prime.numbers_tested) + " numbers tested for primality. Primes found: "
                      + str(get_prime_pair.primes_found))

                return prime_one, prime_two

        # add this current prime into the list for testing
        primes_list.append(prime_one)







########## DETERMINE LANGUAGE ##########


# This function figures out whether the data is in English. Adjust threshold as necessary. Also return percent english
def is_english_bag_of_words(data:str) -> (bool, float):
    """
    This function checks a string of data for English words. If it is mostly in English, the decryption has probably
    succeeded. This function uses the bag of words approach, in which the given data is separated into words, and
    the words are checked against a set of english words.

    :param data: (str) Check this for English
    :return:     (bool) indicates whether or not the text is in english
    :return:     (float) the percentage of words that are in english
    """

    # Create inner static variable of set of english words. Load into this the first time this function is called
    if not hasattr(is_english_bag_of_words, "english_words"):
        is_english_bag_of_words.english_words = set(line.strip()
                                                    for line in open("Resources/Library/English_Words.txt"))




    # Remove punctuation from the data
    data = data.replace("," , "")
    data = data.replace(".", "")
    data = data.replace(";", "")
    data = data.replace("?", "")
    data = data.replace("!", "")
    data = data.replace("-", " ")
    data = data.replace("\"", "")
    data = data.replace("/", "")
    data = data.replace("'s ", " ")
    data = data.replace("'", "")
    data = data.replace(")", "")
    data = data.replace("(", "")

    # Remove digits from the data
    data = data.replace("0", "")
    data = data.replace("1", "")
    data = data.replace("2", "")
    data = data.replace("3", "")
    data = data.replace("4", "")
    data = data.replace("5", "")
    data = data.replace("6", "")
    data = data.replace("7", "")
    data = data.replace("8", "")
    data = data.replace("9", "")




    # Percent of text that is english needed to pass as plaintext
    percent_english_threshold = 0.45
    average_english_word_len_loose = 10
    num_letters = len(data)
    data_expected_words = int(len(data) / average_english_word_len_loose)

    words = data.split()

    # if total_words is overly small(because wrong decryption), take expected words instead
    num_words = len(words)
    total_words = max( num_words, data_expected_words)

    english_word_counter = 0



    for word in words:
        if word.lower() in is_english_bag_of_words.english_words:
            english_word_counter = english_word_counter + 1

    #  If it passes the percent english threshold, return true and the percent english
    if (english_word_counter / total_words) >= percent_english_threshold:
        return True, (english_word_counter / total_words)


    # Else, return False and also the percent english
    return False, (english_word_counter / total_words)





# This function figures out whether data is in English. TODO
def is_english_n_grams(data:str) ->(bool, float):
    """
    This checks a string of data for ngrams, where the grams are letters. If these ngrams match the ngrams expected
    in English, it is probably in english. Possible ngram values are 1-9 (recommended: 2)

    The frequencies of the ngrams are converted into their logarithms (log(frequency)). This is done so that that
    frequency values of the ngrams are not multiplied together to find the final fitness, have their logarithms added
    together.

    The fitness of this data is then compared against the fitness_threshold to determine if it is english.

    :param data: (str) Check this for english
    :return:     (bool) whether or not the data is in english
    :return:     (float) the percent English's most common ngrams found in data's most common ngrams
    """

    # The type of ngram that we are using
    ngram_type = 2


    # Create inner static variable of dictionary that maps ngrams to its frequency.
    if not hasattr(is_english_n_grams, "ngram_to_frequency"):
        is_english_n_grams.ngram_to_frequency = {}

        # Read data from csv-formatted text file
        with open("Library/ngrams" + str(ngram_type) + ".txt", newline='') as my_file:
            reader = csv.DictReader(my_file, fieldnames=("ngram", "count"))
            # Read each row as key-value pair
            for row in reader:
                is_english_n_grams.ngram_to_frequency[row["ngram"]] = row["count"]

    # Create inner static variable of dictionary that maps ngrams to posiitonal index(1 for most common 2 for second...)
    if not hasattr(is_english_n_grams, "ngram_to_positional_index"):
        is_english_n_grams.ngram_to_positional_index = {}

        # Fill out ngram_to_positional_index
        count = 1
        for x in is_english_n_grams.ngram_to_frequency:
            is_english_n_grams.ngram_to_positional_index[x] = count
            count += 1


    # The percent of most common ngrams in the data compared with the most common ngrams in English to qualify as it
    similarity_english_threshold = 0.1


    # Remove all non-letters from the data (replace with space)
    data = data.replace("'s ", " ")
    data = list(data)
    for x in range(0, len(data)):
        if not str.isalpha(data[x]):
            data[x] = " "
    data = "".join(data)




    # Dictionary to store ngrams with their frequencies
    data_ngrams_frequencies = {}

    # Store the ngrams from data into data_ngrams(Skip spaces)
    for x in range(0, len(data) - ngram_type + 1):

        # If on space, then skip it
        if data[x] == " ":
            continue

        ngram = data[x: x + ngram_type]

        # if ngram already exists, then increment value
        if ngram in data_ngrams_frequencies:
            data_ngrams_frequencies[ngram] += 1
        # Else does not exist, so append
        else:
            data_ngrams_frequencies[ngram] = 1


    # Get lists of the ngrams sorted by their frequencies
    most_frequent_ngrams_data = sorted(data_ngrams_frequencies, key=data_ngrams_frequencies.get)
    most_frequent_ngrams_english = sorted(is_english_n_grams.ngram_to_frequency,
                                          key=is_english_n_grams.ngram_to_frequency.get)

    # convert the ngrams into lists of positional index frequencies
    i = 0
    for x in most_frequent_ngrams_data:
        most_frequent_ngrams_data[i] = is_english_n_grams.ngram_to_positional_index.get(x)
        i += 1

    i = 0
    for x in most_frequent_ngrams_english:
        most_frequent_ngrams_english[i] = is_english_n_grams.ngram_to_positional_index.get(x)
        i+= 1



    # This inner function returns a value between 0 and 1 indicating how close these two lists are. Take into account
    # ordering of the lists. Lists must be the same size
    def similarity_of_two_integer_lists(x, y):
        """
        Figure out how close these values are

        :param x: (list) one of the lists to compare to
        :param y: (list) another of the list to compare to
        :return: (float) value between 0 and 1 indicating the similarity
        """

        # Size of the arrays
        size = len(y)

        # Add points to this
        total_points = 0

        for i in range(size):
            points_this_index = 1 / size

            # Figure out the distance between x[i] and that value in y. If does not exist, 0 points
            if x[i] not in y:
                continue

            # At this point, x[i] is in y at some index j. Find abs(i - j)
            j = y.index(x[i])
            difference = abs(i - j)

            # Find out difference as a proportion of the overall length of the list
            difference = difference / size

            # Calculate the amount of points for x[i]
            points_this_index = points_this_index * (1 - difference)

            # Add to total points
            total_points = total_points + points_this_index

        return total_points


    """
    # Obtain the similarity between most frequent ngrams of data and of english
    similarity = difflib.SequenceMatcher(None, most_frequent_ngrams_data, most_frequent_ngrams_english)
    similarity_english = similarity.ratio()
    """

    similarity_english = similarity_of_two_integer_lists(most_frequent_ngrams_data, most_frequent_ngrams_english)
    # If text is in english
    if similarity_english >= similarity_english_threshold:
        return True, similarity_english

    else:
        return False, similarity_english















############################################################################################ HELPER FUNCTIONS ##########

#  Returns alphabet. This helper function asks the user for a character set.
def _take_alphabet(alphabets:list) -> str:
    """
    This functions asks the user to input a selection(a alphabet). THis selection is compared against ALPHABETS
    in order to make sure that it is a valid selection

    :param alphabets: (list) the list of all character sets
    :return: (string) the user-entered character set
    """


    previous_entry_invalid = False
    #  TAKE AN INPUT FOR THE CHARACTER SET
    while True:

        #  Print out the prompt for the user. If the previous entry was invalid, say so
        if not previous_entry_invalid:
            selection = input("Enter the character set to be used (for ciphertext): ")
        else:
            selection = input("Character set invalid! Enter a new character set (for ciphertext): ")
            previous_entry_invalid = False

        # Print out the available character sets, then continue
        if selection[0:4] == "info":
            print("The available character sets are: ")
            for x in range(0, len(alphabets)):
                print("                                  " + alphabets[x])
            continue

        # Test that the user entry is a valid character set. If so, exit out of the forever loop
        broken = False
        for x in range(0, len(alphabets)):
            if selection.rstrip() == alphabets[x]:
                broken = True
                break
        if broken == True:
            break

        # If here, that means the entry was invalid. Loop again
        previous_entry_invalid = True
    # END OF FOREVER LOOP TO TAKE A CHARACTER SET



    # figure out the end_char of the character set
    end_char = CHAR_SET_TO_SIZE.get(selection)

    return selection


#  Returns char_encoding_scheme. This helper function asks the user for a character encoding scheme.
def _take_char_encoding_scheme(binary_to_char_encoding_scheme:list) -> str:
    """
    This functions asks the user to input a selection(a char encoding scheme. The selection is compared against hte
    given list to ensure that it is a legitimate selection

    :param binary_to_char_encoding_scheme: (list) the list of all character encoding schemes
    :return:                               (str) the user-entered character set
    """


    previous_entry_invalid = False
    #  TAKE AN INPUT FOR THE CHARACTER SET
    while True:

        #  Print out the prompt for the user. If the previous entry was invalid, say so
        if not previous_entry_invalid:
            selection = input("Enter the character encoding scheme to be used (for ciphertext): ")
        else:
            selection = input("Character encoding scheme invalid! Enter a new scheme (for ciphertext): ")
            previous_entry_invalid = False

        # Print out the available character sets, then continue
        if selection[0:4] == "info":
            print("The available character encoding schemes are: ")
            for x in range(0, len(binary_to_char_encoding_scheme)):
                print("                                  " + binary_to_char_encoding_scheme[x])
            continue

        # Test that the user entry is a valid character set. If so, exit out of the forever loop
        broken = False
        for x in range(0, len(binary_to_char_encoding_scheme)):
            if selection.rstrip() == binary_to_char_encoding_scheme[x]:
                broken = True
                break
        if broken:
            break

        # If here, that means the entry was invalid. Loop again
        previous_entry_invalid = True
    # END OF FOREVER LOOP TO TAKE A CHARACTER SET



    # figure out the end_char of the character encoding scheme
    end_char = CHAR_SET_TO_SIZE.get(selection)

    return selection


# This helper function asks the user for a char set of a small ciphertext (less than 300)
def _take_char_set_of_short_text(text_len:int, char_set:list) -> str:
    """
    For shorter texts, the character set cannot be accurately determined automatically. For these cases, then ask the
    user for the character set. Character sets must be legitimate.

    :param text_len: (int)  the length of the data. (Is short)
    :param char_set: (list) either the ALPHABETS or BINARY_TO_CHAR_ENCODING_SCHEMES
    :return:         (str)  the name of the character set that is chosen
    """

    # Determine the character set type (alphabet or encoding scheme)
    if char_set == ALPHABETS:
        options = "alphabet"
    else:
        options = "encoding scheme"


    # Ask for the user input
    user_choice = input("Ciphertext with " + str(text_len) + " characters is too short to accurately determine its "
                            + options + ". Manually enter the " + options + ": ")


    # While the user's choice is invalid, keep looping. Break when user entry is valid
    while True:

        # If valid alphabet
        if char_set == ALPHABETS and user_choice in ALPHABETS:
            break

        # If valid encoding scheme
        if char_set == BINARY_TO_CHAR_ENCODING_SCHEMES and user_choice in BINARY_TO_CHAR_ENCODING_SCHEMES:
            break

        # If not valid alphabet
        if char_set == ALPHABETS:
            user_choice = input(user_choice + " is not a valid alphabet! Try again: ")
            continue

        # If not valid encoding scheme
        if char_set == BINARY_TO_CHAR_ENCODING_SCHEMES:
            user_choice = input(user_choice + " is not a valid encoding scheme! Try again: ")
            continue

    return user_choice




# This helper function obtain a single char key from the user and returns that
def _get_single_char_key() ->str:
    """
    This function obtains a key from the user that must be a single character

    :return: (str) the single character key
    """

    # TAKE A KEY
    key = input("Enter a key (single character only): ")

    # While the key is not valid, ask user to enter a key again
    while True:
        # If the user did not enter a key, ask the user to enter one
        if key == "":
            key = input("No key given! Enter a key (single character only): ")
            continue

        # IF THE USER DID NOT GIVE A SINGLE CHARACTER, FORCE THE USER TO ENTER IT AGAN
        if len(key) != 1:
            key = input("Not a single character! Enter a key (single character only): ")
            continue

        # All checks passed, so break out of the for loop
        break

    return key



# This help function obtains a general key from the user and returns that
def _get_general_key() -> str:
    """
    This function obtains a key of any length fro the user

    :return: (str) the user-entered key
    """

    # TAKE A KEY
    key = input("Enter a key: ")

    # IF THE USER DID NOT GIVE ANYTHING, SEND AN ERROR MESSAGE AND FORCE THE USER TO ENTER IT AGAN
    while key == "":
        key = input("No key given! Enter a key: ")

    return key


# This helper function obtains a private key from the user
def _get_private_key() -> str:
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
def _get_public_key() -> str:
    """
    This function obtains a public key from the user. If nothing entered, then the user wants to generate a key.

    :return: (str) the user-entered key
    """

    # Take a key
    key = input("Enter the public key (Leave empty to generate public/private keys): ")

    return key































