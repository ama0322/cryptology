from Cryptography.Ciphers._cipher import Cipher   # To get access to type Cipher
from   typing                     import Callable # To get access to type Callable
import secrets # To generate cryptographically secure numbers
import random  # To generate random numbers
import base64  # To get access to encoding schemes
import codecs  # To perform "utf-8" encoding/decoding
import time    # To time various processes
import csv     # To read csv format
import copy    # To make deep-copies
import sys     # To get access to the system (to suppress print() calls)
import os      # To get access to os         (to suppress print() calls)
import math    # TO get various math functions

################################################################################################### RESOURCES ##########








########################################################################################### USEFUL ALGORITHMS ##########

########## MISCELLANEOUS ##########
# region Miscellaneous
# This decorator gives static vars to the decorated function. Parameters: (static_one=1, static_two=2, ...)
def static_vars(**kwargs:dict):
    def decorate(function_to_decorate):
        for k in kwargs:
            setattr(function_to_decorate, k, kwargs[k])
        return function_to_decorate
    return decorate

# This decorator sets the object's instance variable with the time it takes for the function to run
def store_time_in(*args:str):

    def decorate_method(method_to_decorate):

        # Same method signature as the wrapped function
        def wrapper(self, *parameters) -> None:

            start_time = time.time()
            output = method_to_decorate(self, *parameters)
            elapsed_time = time.time() - start_time + 0.00000000000000001      # Prevent the time from being 0.0

            for arg in args:                     # Store the time in all kwargs
                exec("{} = elapsed_time".format(arg))


            return output

        return wrapper
    return decorate_method

# This decorator sets the time_for_algorithm with (time_overall - time_for_keys). Used on encrypt() or decrypt()
def get_time_for_algorithm(time_for_algorithm:str, time_overall:str, time_for_keys:str):

    def decorate_method(method_to_decorate):

        # Same method signature as the wrapped function
        def wrapper(self) -> None:

            # Run the method as usual, and save the result
            result = method_to_decorate(self)

            # Calculate and set the time_for_algorithm
            exec("{} = {} - {}".format(time_for_algorithm, time_overall, time_for_keys))

            # Return the result
            return result

        return wrapper
    return decorate_method


# Disable print() calls by setting the standard output to null
def disable_print() -> None:
    sys.stdout = open(os.devnull, 'w')

# Restore by resetting the standard output to what it should be
def enable_print() -> None:
    sys.stdout = sys.__stdout__

# Function of ord() that automatically adjusts for surrogates
def ord_adjusted(character:str) -> int:
    """
    Because the regular ord doesn't adjust for surrogates, this one does.

    :param character: (str) The character to get the ord() of, adjusted for surrogates
    :return:          (int) The adjusted ord() result
    """

    ord_result = ord(character[0])


    # Adjust the ord result
    if ord_result >= 57343:               # 55296 is the UPPER INCLUSIVE bound of the surrogates
        ord_result = ord_result - 2048    # 2048 is the number of surrogate characters

    return ord_result

# Function of chr() that automatically adjusts for surrogates
def chr_adjusted(unicode_val:int) -> str:
    """
    Same as chr() but adjusts to skip surrogates

    :param unicode_val: (int) the unicode value to get the char of
    :return:            (str) the character to return
    """

    # Adjust the unicode value if necessary
    if unicode_val >= 55296:                # 55296 is the LOWER INCLUSIVE bound of the surrogates
        unicode_val = unicode_val + 2048    # 2048 is the number of surrogate characters

    return chr(unicode_val)

# This function formats a list of strings to line up with the colon. The entire thing can be right-shifted
def format_to_colon(lines: list, column=35) -> list:
    """
    This formats lines so that the colons line up. In addition, the entire thing can be right-shifted.

    :param lines:       (list) The list of strings to format
    :param column:      (int)  The column index where the colons should be. Overridden if too small
    :return:            (list) The list of formatted strings
    """

    # Figure out the index of the colon that is furthest out. Override with "column" parameter if necessary
    max_len = max(max(line.find(":") for line in lines), column)

    for i in range(0, len(lines)):
        if lines[i].find(":") == -1:  # If no colon in the line, then just skip
            continue
        lines[i] = " " * (max_len - lines[i].find(":")) + lines[i]

    # return the new strings
    return lines

# Allow division by zero
def safe_div(x:int,y:int):
    if y == 0:
        return 0
    return x / y

# Modular multiplicative inverse
def mod_inverse(x:int, modulus:int) -> int:
    """
    This finds the modular multiplicative inverse of a. "x" and "modulus" be coprime
    1. "xa + yb = gcd(a, b)"       : Start with the extended euclidean algorithm to find x in this equation
    2. "xa + ym = 1"               : Substitute "b" for "m". Simplify "gcd(x, m)" to "1" because "x" and "m" are coprime
    3. "xa + ym = 1 (mod modulus)" : Take modulo "m" on both sides
    4. "xa = 1 (mod modulus)"      : "ym" under "(mod m)" simplifies to "0". The modular inverse is "a" in this equation

    :param x:       (int) The number to find the inverse of
    :param modulus: (int) The modulus to find the inverse under
    :return:        (int) The modular multiplicative inverse of a
    """

    # Extended euclidean algorithm
    a, b, u = 0, modulus, 1
    while x > 0:
        # Figure out the integer quotient
        quotient = b // x

        # Update for next iteration
        # noinspection PyRedundantParentheses
        x, a, b, u = (b % x), (u), (x), (a - quotient * u)




    # Calculate the modular multiplicative inverse by a % m
    if b != -1:
        return a % modulus





# This function splits utf-8 text into integer blocks, each of them having block_size bits
@static_vars(update_interval=1000)
def utf_8_to_int_blocks(text:str, block_size:int) -> list:
    """
    This splits utf-8 text into integer blocks, each of them having block_size bits. The block in index 0 may be smaller
    than block_size, due to division remainder

    :param text:       (str)  The utf-8 text to split up
    :param block_size: (int)  The size of the blocks to split into
    :return:           (list) The list of blocks that were split up
    """

    # Convert to bits
    text = text.encode("utf-8").hex()              # First, change to hex digits
    text = bin(int(text, 16))[2:].lstrip("0")      # Convert to binary, remove leading "0b" characters and 0's


    # Important variables
    text_blocks = []               # Build up the blocks here
    text_len    = len(text)        # Save the text length here (in hex digits)


    # Read in blocks from the text
    text_index = len(text)                                                  # Read from end-to-front
    while text_index > 0:                                                   # While there is still text to process
        block = text[max(0, text_index - block_size):text_index]                # read one block from end
        text_blocks.append(int(block, 2))                                       # Append block (reverse later)
        text_index = text_index - block_size                                    # Update index
        if len(text_blocks) % utf_8_to_int_blocks.update_interval == 0:
            print("To encryption blocks: {:.2%}".format(len(text_blocks) * block_size / text_len) )


    # Reverse the blocks (because we read from end to beginning)
    text_blocks.reverse()


    return text_blocks


# This function turns integer blocks into text using an encoding scheme
def int_blocks_to_encoded_chars(int_blocks:list, encoding:str, block_size:int) -> str:
    """
    This turns the list of integer blocks into text using an encoding scheme. This is done by encoding each
    individual block, and then concatenating them all together.

    :param int_blocks: (list) The list of integer blocks
    :param encoding:   (str)  The name of the encoding to use
    :param block_size: (int)  The number of bits in the block to pad up to
    :return:           (str)  The encoded text
    """


    text = ""                  # Build up the character-encoded text here
    char_blocks = []           # The list of character blocks

    # Get the character-encoded blocks
    for i in range(0, len(int_blocks)):
        char_blocks.append(int_to_chars_encoding_scheme_pad(int_blocks[i], encoding, block_size))
        if i % utf_8_to_int_blocks.update_interval == 0:
            print("Encoding to characters: {:.2%}".format( safe_div(i, (len(int_blocks) - 1)) ) )


    # Concatenate all the blocks
    text = "".join(char_blocks)

    # Return text
    return text


# This function turns encoded characters into integer blocks, given a block_size to use
def encoded_chars_to_int_blocks(encoded_chars:str, encoding:str, block_size:int) -> list:
    """
    This turns encoded characters into int blocks, given a block_size to use.

    :param encoded_chars: (str)  The string to convert into int blocks
    :param encoding:      (str)  The name of the character encoding to use to decode
    :param block_size:    (int)  The size, in bits, of each of the blocks
    :return:              (list) The list of integer blocks
    """

    # Build up the integer blocks here
    int_blocks = []

    # Figure out how many characters in a block
    chars_in_block = len(int_to_chars_encoding_scheme_pad(0, encoding, block_size))

    # Read in the blocks, and decode them to int
    encoded_chars_index = 0
    while encoded_chars_index < len(encoded_chars):
        char_block = encoded_chars[encoded_chars_index : encoded_chars_index + chars_in_block]
        int_blocks.append(chars_to_int_decoding_scheme(char_block, encoding))
        encoded_chars_index += chars_in_block
        if len(int_blocks) % utf_8_to_int_blocks.update_interval == 0:
            print("Decoding to integer blocks: {:.2%}".format( safe_div(encoded_chars_index,
                                                                        (len(encoded_chars) - 1)) ))


    # Return the integer blocks
    return int_blocks


# This function turns integer blocks into utf-8 text
def int_blocks_to_utf_8(int_blocks:list, block_size:int) -> str:
    """
    This converts integer blocks into utf-8 text. This is done by converting the int blocks into binary blocks,
    padded up to block_size. Then, all the binary blocks are concatenated together. The concatenated binary string is
    then converted to a long hex string, which is then decoded to utf-8 text.

    :param int_blocks: (list) The list of integer blocks to decode
    :param block_size: (int)  The size, in bits, of each block
    :return:           (str)  The decoded utf-8 text
    """

    # Build up the text here
    text = ""


    # Convert all the integer blocks to binary string blocks (remove leading "0b" and pad up to block_size)
    bin_blocks = []
    for i in range(0, len(int_blocks)):                  # Turn int blocks to binary blocks
        block = int_blocks[i]                                # Get the block
        if i == 0:                                           # Do NOT pad the first block
            block = bin(block)[2 : ]                             # Just remove the leading "0b"
        elif i != 0:                                         # Pad the non-first blocks
            block = format(block, "0{}b".format(block_size))     # Convert to bin and pad with zero's up to block_size

        bin_blocks.append(block)
        if i % utf_8_to_int_blocks.update_interval == 0:
            print("Converting integer blocks UTF-8: {:.2%}".format( safe_div(i , len(int_blocks) - 1) ))


    # Concatenate all the binary blocks
    bin_text = "".join(bin_blocks)

    # Convert the binary string to a hex string ("remove leading 0x")
    hex_text = hex(int(bin_text, 2))[2 : ]

    # Decode the hex to utf-8
    text = bytearray.fromhex(hex_text).decode("utf-8")

    # return text
    return text






# endregion


########## RELEVANT TO GENERATING A CIPHER OBJECT ##########
# region For generating a cipher object
# Figure out the ClassName for the given module name
def get_class_name(module:str) -> str:
    module = module.capitalize()                 # Capitalize the first letter
    while module.find("_") != -1:                # Process all of the "_" characters

        underscore_index = module.find("_")                      # Find the first underscore
        capitalized = module[underscore_index + 1].upper()       # Capitalize the letter right after

        # Remove the first underscore, and replace the immediately following character with capitalized version
        module = module[0:underscore_index] + capitalized + module[underscore_index + 2:len(module)]

    return module


# Figure out the character set of the given data automatically if possible. Inaccurate for short texts
# noinspection SpellCheckingInspection
@static_vars(short_text_len=300)
def get_char_set(data: str, cipher_char_set: str, is_encrypt:bool) -> str:
    """
    This calculates the character set of the given data. If the text given is ciphertext, then the user will be
    prompted to manually enter in the char_set for short texts. Otherwise, if the text given is plaintext,
    then figure it out automatically.

    :param data:            (str)  The data to analyze for char_set
    :param cipher_char_set: (str)  Either "alphabet" or "encoding scheme"
    :param is_encrypt:      (bool) If is encrypt, then ask the use for a character set. If not, try to calculate it.
    :return:                (str)  The name of the char_set that the data is in
    """

    # If is in encrypt, then ask the user manually for a character set. User can enter a default character set.
    if is_encrypt is True:
        # Set the default character set and the available options, based on cipher_char_set
        if cipher_char_set == "alphabet":
            default_selection = "unicode"
            options = Cipher.ALPHABETS
        else:
            default_selection = "base64"
            options = Cipher.ENCODING_SCHEMES

        # Print out the prompt for the user
        user_choice = input("Enter the {} to be used for the ciphertext (or to use the default {}, \"{}\", "
                          "leave empty): ".format(cipher_char_set, cipher_char_set, default_selection))

        # Loop while the user gives an invalid alphabet. If valid, then break
        while True:

            # If the user asks for help
            if user_choice == "info":
                print("The available %ss are: " % cipher_char_set, end="")
                for option in options:

                    if option == "ascii":
                        print(" " * (45 - len("The available Cipher.ALPHABETS are: ")) + option)

                    elif option == "base16":
                        print(" " * (45 - len("The available encoding schemes are: ")) + option)

                    else:
                        print(" " * 45 + option)

                        user_choice = input("\nEnter the %s to be used for the ciphertext (or to use the default "
                                            "%s, \"%s\", leave empty): "
                                            % (cipher_char_set, cipher_char_set, default_selection))
                continue

            # User wants default char_set
            elif user_choice == "":
                user_choice = "unicode_plane0"
                break

            # Invalid option
            elif user_choice.rstrip() not in options:
                user_choice = input("Invalid %s (%s)! Try again: " % (cipher_char_set, user_choice.rstrip()))
                continue

            # If here, then user gave valid option. All clear
            else:
                break

        return user_choice


    # Ciphertext is too short. Must manually ask user for the character set
    if is_encrypt is False and len(data) <= get_char_set.short_text_len:

        # Ask for the user input
        user_choice = input("Ciphertext with %d characters is too short to accurately determine its %s. "
                            "Manually enter the %s: " % (len(data), cipher_char_set, cipher_char_set))

        # While the user's choice is invalid, keep looping. Break when user entry is valid
        while True:

            # If valid alphabet
            if cipher_char_set == "alphabet" and user_choice in Cipher.ALPHABETS:
                break

            # If valid encoding scheme
            if cipher_char_set == "encoding scheme" and user_choice in Cipher.ENCODING_SCHEMES:
                break

            # Invalid choice, ask for another input
            user_choice = input("\"%s\" is not a valid %s! Try again: " % (user_choice, cipher_char_set))

        return user_choice


    # Data is long enough or is plaintext, figure it out automatically
    elif is_encrypt is False and len(data) > get_char_set.short_text_len:
        if cipher_char_set == "alphabet":
            # first pass through ciphertext, check if there are unicode characters (65536 and above)
            for x in data:
                if ord(x) >= 65536:
                    return "unicode"

            # second pass through ciphertext, check if there are unicode_plane0
            for x in data:
                if ord(x) >= 256:
                    return "unicode_plane0"

            # third pass through ciphertext, check if there are extended_ascii characters(128 and above)
            for x in data:
                if ord(x) >= 128:
                    return "extended_ascii"

            # Otherwise, only ascii characters
            return "ascii"

        elif cipher_char_set == "encoding scheme":
            # If characters only in base16 char_set, return "base16"
            if all(character in "0123456789ABCDEF" for character in data):
                return "base16"

            # Test base32 char_set
            if all(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for character in data):
                return "base32"

            # Test base64 char_set
            if all(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                   for character in data):
                return "base64"

            # Test base85 char_set
            if all(character in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>"
                                "?@^_`{|}~"
                   for character in data):
                return "base85"

            # Test ascii char_set
            if all(0 <= ord(character) < 128 for character in data):
                return "extended_ascii"

            # Test extended_ascii char_set
            if all(0 <= ord(character) < 256 for character in data):
                return "extended_ascii"

            # Else, is in base4096
            if all(0 <= ord(character) < 4096 for character in data):
                return "base4096"




# Adjust the alphabet if necessary. Some encryption ciphers need the ciphertext alphabet >= plaintext alphabet
def adjust_alphabet(data: str, alphabet: str, cipher_char_set: str, restrict_alphabet: bool) -> str:
    """
    Some ciphers cannot work correctly if the chosen ciphertext alphabet is smaller than the plaintext's alphabet.
    They require at minimum the plaintext's alphabet to decrypt correctly. So switch to use the plaintext's alphabet
    for encryption, and inform the user.

    :param data:              (str)  The text
    :param alphabet:          (str)  The selected alphabet. Needs to be checked
    :param cipher_char_set:   (str)  Either "alphabet" or "encoding scheme"
    :param restrict_alphabet: (bool) indicates whether restricting (adjusting) the alphabet is necessary
    :return:                  (str)  The adjusted alphabet (or non-adjusted if adjustment is unnecessary)
    """


    if restrict_alphabet == False:  # If alphabet restriction not necessary, just return
        return alphabet

    # Figure out the "true" alphabet of the plaintext. Temporarily suspend the short text limit
    original_short_len = copy.deepcopy(get_char_set.short_text_len)
    get_char_set.short_text_len = -1
    true_alphabet = get_char_set(data, cipher_char_set, False)
    get_char_set.short_text_len = original_short_len

    # If the "true alphabet" is larger than the chosen alphabet, then inform user automatically switch
    if Cipher.ALPHABETS.get(true_alphabet) > Cipher.ALPHABETS.get(alphabet):
        print("The chosen alphabet for encryption \"%s\" is insufficient for the alphabet that the plaintext is in. "
              "Therefore, the alphabet for encryption is switched to: \"%s\"" % (alphabet, true_alphabet))
        return true_alphabet

    # Otherwise, all clear, return the user-selected alphabet
    else:
        return alphabet
# endregion







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
        number = number.to_bytes( (key_size + 7) // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b16encode(number))[2: -1]

    # If base32
    elif encoding == "base32":
        # Turn the number into a bytearray(Calculate bytes needed with key_size / 8)
        number = number.to_bytes( (key_size + 7) // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b32encode(number))[2: -1]

    # If base 64
    elif encoding == "base64":

        # Turn the number into a bytearray(Calculate bytes needed with key_size / 8)
        number = number.to_bytes( (key_size + 7) // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b64encode(number))[2: -1]


    # If base 85
    elif encoding == "base85":

        # Turn the number into a bytearray(Calculate bytes needed with key_size / 8)
        number = number.to_bytes( (key_size + 7) // 8 ,byteorder="big")

        # Encode the bytearray using base64. Turn the resulting encoded bytearray into a string. Remove "b'" and "'"
        encoded = str(base64.b85encode(number))[2: -1]


    # If extended_ascii, turn int to bits. Read bits 8 at a time. Pad "0" in front if necessary
    elif encoding == "ascii":

        # Turn the integer into a string with binary representation. Get rid of leading "0b"
        number = bin(number)[2:]

        # Pad the front if necessary (all the way up to key_size and divisible by 8)
        if len(number) < key_size:
            number = (key_size - len(number)) * "0" + number
        if len(number) % 7 != 0:
            number = (7 - (len(number) % 7)) * "0" + number

        # Read bits 8 at a time. Interpret those 8 bits as extended_ascii(unicode) and add to encoded
        while number != "":
            encoded += chr( int(number[0:7], 2) )
            number = number[7:]


    # If extended_ascii, turn int to bits. Read bits 8 at a time. Pad "0" in front if necessary
    elif encoding == "extended_ascii":

        # Turn the integer into a string with binary representation. Get rid of leading "0b"
        number = bin(number)[2:]

        # Pad the front if necessary (all the way up to key_size and divisible by 8)
        if len(number) < key_size:
            number = (key_size - len(number)) * "0" + number
        if len(number) % 8 != 0:
            number = (8 - (len(number) % 8)) * "0" + number

        # Read bits 8 at a time. Interpret those 8 bits as extended_ascii(unicode) and add to encoded
        while number != "":
            encoded += chr( int(number[0:8], 2) )
            number = number[8:]

    # If base4096, read 12 bits at a time. Interpret this as unicode
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
    elif encoding == "ascii":

        # Turn the integer into a string with binary representation. Get rid of leading "0b"
        number = bin(number)[2:]

        # Pad the front if necessary (all the way up to nearest byte, so divisible by 8)
        if len(number) % 7 != 0:
            number = (7 - (len(number) % 7) ) * "0" + number

        # Read bits 8 at a time. Interpret those 8 bits as extended_ascii(unicode) and add to encoded
        while number != "":
            encoded += chr( int(number[0:7], 2) )
            number = number[7:]


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

        # Pad the front if necessary(make divisible by 12)
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
    elif encoding == "ascii":

        # Build up binary string here
        bin_string = ""

        # Loop through string. Add the extended_ascii characters one at a time to bin_string (in binary form).
        for x in string:

            # Obtain binary form of the extended_ascii character. Remove leading "0b"
            eight_bits = bin(ord(x))[2:]

            # Pad to eight digits if necessary
            if len(eight_bits) % 7 != 0:
                eight_bits = (7 - len(eight_bits) % 7) * "0" + eight_bits

            #Add to bin string
            bin_string += eight_bits


        # Read the binary string as an integer
        decoded = int(bin_string, 2)


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

    elif encoding == "ascii":

        # Change string to hex format with utf-8
        hex = string.encode("utf-8").hex()

        # Change hex string into a binary string (remove leading "0b")
        bin_str = bin(int(hex, 16))[2:]



        # Read bits seven at a time. Interpret them as ascii
        while bin_str != "":
            encoded += chr( int(bin_str[0:7], 2) )
            bin_str = bin_str[ 7: ]




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



    elif encoding == "ascii":

        decoded = ""
        for char in string:
            # Convert each ascii to 7 bits, and concatenate all of it together. Pad up to seven bits
            decoded = bin(ord(char))[2:]
            decoded = (7 - (len(decoded) % 7)) * "0" + decoded


        # Turn the bitstring into a regular string with utf-8 encoding
        decoded = codecs.decode(decoded, "hex").decode("utf-8") # Decode bytes to string using utf-8





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

# This function returns a pair of primes whose product is of size prime_bits
@static_vars(primes_found=0)
def generate_prime_pair(prime_bits: int) -> (int, int):
    """
        Figures out a pair of primes whose product is of size prime_bits. When a prime is found, it is multiplied against
         all the primes in primes_list to try to find a pair that gives a correct size key. If one is not found,
        this prime is added to the list, and a new prime number is searched for.

        :param prime_bits: (int) the bit length of the key (the product of the primes)
        :return:           (int) One prime number that is the factor of the key
        :return:           (int) Another prime number that is the factor of the key
        """

    # the function to generate large primes. Pass in bit_length for the desired size of the generated prime
    @static_vars(numbers_tested=0)
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
                103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
                211,
                223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331,
                337,
                347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457,
                461,
                463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
                601,
                607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
                739,
                743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877,
                881,
                883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019,
                1021,
                1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123,
                1129,
                1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259,
                1277,
                1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399,
                1409,
                1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
                1511,
                1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619,
                1621,
                1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753,
                1759,
                1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889,
                1901,
                1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027,
                2029,
                2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143,
                2153,
                2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293,
                2297,
                2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411,
                2417,
                2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557,
                2579,
                2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693,
                2699,
                2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803,
                2819,
                2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957,
                2963,
                2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109,
                3119,
                3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257,
                3259,
                3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389,
                3391,
                3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533,
                3539,
                3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659,
                3671,
                3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797,
                3803,
                3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929,
                3931,
                3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079,
                4091,
                4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229,
                4231,
                4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363,
                4373,
                4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517,
                4519,
                4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
                4663,
                4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801,
                4813,
                4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967,
                4969,
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

            :param num:           (int) number to test for primeness
            :param times_to_test: (int) the number of time to test rabin-miller
            :return:              (boolean) indicates whether the number is prime
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

        # Loop until a prime number has been generated
        while True:

            # Generate a number that needs to be tested for primality
            num_to_test = secrets.randbits(bit_length) ^ (1 << (bit_length - 1))

            # Print updates and update
            print(str(generate_prime.numbers_tested) + " numbers tested for primality. Primes found: "
                  + str(generate_prime_pair.primes_found))
            generate_prime.numbers_tested += 1

            # Set the lowest bit to 1 to make the number odd.
            num_to_test = num_to_test | 1

            # While small primes test fails, update number with += 2. Do until number no longer fits.
            test_result, failed_prime = small_primes_primality_test(num_to_test)
            while test_result == False and num_to_test.bit_length() == bit_length:
                # Print updates
                print(str(generate_prime.numbers_tested) + " numbers tested for primality. Primes found: "
                      + str(generate_prime_pair.primes_found))
                generate_prime.numbers_tested += 1

                # Update the number, and run small primes test again
                num_to_test += 2
                test_result, failed_prime = small_primes_primality_test(num_to_test)


            # If failed the small_primes_primality_test, then generate new number
            if test_result == False:
                continue

            # If failed fermat's little theorem, then generate new number
            if fermat_primality_test(num_to_test) == False:
                continue

            # If the generated number was prime, then return
            if rabin_miller_primality_test(num_to_test, 64):
                return num_to_test


    # If prim_bits is odd, then, I will have to generate primes of a slightly different bit_length
    if prime_bits % 2 != 0:
        # Create the list with one prime number is in it(primes are about half the size of prime_bits)
        primes_list = [generate_prime(prime_bits // 2)]; generate_prime_pair.primes_found += 1

        # Loop until two prime numbers are found whose product is the correct size (prime_bits)
        for i in range(1, sys.maxsize**10):

            # Alternate between generating primes of size (prime_bits // 2) and ((prime_bits // 2) + 1)
            if i % 2 == 0: prime_one = generate_prime(prime_bits // 2); generate_prime_pair.primes_found += 1
            else:          prime_one = generate_prime((prime_bits // 2) + 1); generate_prime_pair.primes_found += 1

            # Test all pairs of primes for a key that is of proper size
            for prime_two in primes_list:

                # If the primes work out to make a key of correct size
                if (prime_one * prime_two).bit_length() == prime_bits:
                    # Print updates
                    print("{} numbers tested for primality. Primes found: {}"
                          .format(generate_prime.numbers_tested, generate_prime_pair.primes_found))

                    return prime_one, prime_two

            # add this current prime into the list for testing
            primes_list.append(prime_one)




    # Else, prime_bits is even, so this is straightforward. Just generate primes that are half the bit_length
    elif prime_bits % 2 == 0:
        # Create the list with one prime number is in it(primes are about half the size of prime_bits)
        primes_list = [generate_prime(prime_bits // 2)]; generate_prime_pair.primes_found += 1

        # Loop until two prime numbers are found whose product is the correct size (prime_bits)
        while True:

            # Generate a prime for testing
            prime_one = generate_prime(prime_bits // 2); generate_prime_pair.primes_found += 1

            # Test all pairs of primes for a key that is of proper size
            for prime_two in primes_list:

                # If the primes work out to make a key of correct size
                if (prime_one * prime_two).bit_length() == prime_bits:
                    # Print updates
                    print("{} numbers tested for primality. Primes found: {}"
                          .format(generate_prime.numbers_tested, generate_prime_pair.primes_found))

                    return prime_one, prime_two

            # add this current prime into the list for testing
            primes_list.append(prime_one)






########## DETERMINE LANGUAGE ##########

# This function figures out whether the data is in English. Adjust threshold as necessary. Also return percent english
@static_vars(english_words=[], percent_english_threshold=0.25, average_word_len=5.1)
def is_english_bag_of_words(data:str) -> (bool, float):
    """
    This function checks a string of data for English words. If it is mostly in English, the decryption has probably
    succeeded. This function uses the bag of words approach, in which the given data is separated into words, and
    the words are checked against a set of english words.

    :param data: (str) Check this for English
    :return:     (bool) indicates whether or not the text is in english
    :return:     (float) the percentage of words that are in english
    """

    # Fill in the english_words the first time this function is called
    if is_english_bag_of_words.english_words == []:
        is_english_bag_of_words.english_words = set(line.strip()
                                                    for line in open("Resources/Algorithm_Resources/English_Words.txt"))

    # Remove punctuation from the data
    data = data.replace(",", "")
    data = data.replace(".", "")
    data = data.replace(";", "")
    data = data.replace("?", "")
    data = data.replace("!", "")
    data = data.replace("-", " ")
    data = data.replace("\n", " ")
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



    words = data.split(" ")



    # Calculate the number words for percentage (actual num of words or expected num of word, whichever is bigger).
    # This is done to prevent a false positive in the case that the entire data is one long word or two or random
    # characters and this somehow is detected as an english word, thereby bringing up the percentage_english higher
    # than it really should be.
    expected_words = len(data) / is_english_bag_of_words.average_word_len
    actual_words = len(words)
    num_words = max(expected_words, actual_words)





    # Count the number of english words
    english_word_counter = 0
    for word in words:
        if word.lower() in is_english_bag_of_words.english_words:
            english_word_counter = english_word_counter + 1

    # Calculate the percentage that is english
    percent_english = (english_word_counter / num_words)



    #  If it passes the percent english threshold, return true and the percent english
    if percent_english >= is_english_bag_of_words.percent_english_threshold:
        return True, percent_english

    # Else, return False and also the percent english
    else:
        return False, percent_english



# This function figures out whether data is in English. TODO
@static_vars(ngram_len=2)
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

    # Create inner static variable of dictionary that maps ngrams to positional index(1 for most common 2 for second...)
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




    similarity_english = similarity_of_two_integer_lists(most_frequent_ngrams_data, most_frequent_ngrams_english)
    # If text is in english
    if similarity_english >= similarity_english_threshold:
        return True, similarity_english

    else:
        return False, similarity_english









########## MODES OF ENCODING ##########

# ECB mode. Just a straightforward encryption on each block. Nothing special
def encrypt_ecb(cipher_obj:Cipher, algorithm:Callable[[int],int], plaintext_blocks:list, key_one:str,
                                                                        key_two:str) -> (list, str, str):
    """
    This runs an encryption in ECB mode.

    :param cipher_obj:       (Cipher)   The cipher object that is encrypting
    :param algorithm:        (Callable) The function that encrypts a block
    :param plaintext_blocks: (list)     The int blocks to encrypt and encode
    :param key_one:          (str)      The original key to append to (nothing in the case of ECB)
    :param key_two           (str)      Another key to append to (Probably the private_key)
    :return:                 (list)     The encrypted ciphertext_blocks
    :return:                 (str)      The new key
    :return:                 (str)      The new private key, if it exists
    """


    ciphertext_blocks = [0] * len(plaintext_blocks)               # Build the ciphertext blocks here



    # Apply the block cipher on each plaintext block to get the ciphertext block
    for i in range(0, len(plaintext_blocks)):
        ciphertext_blocks[i] = algorithm(plaintext_blocks[i])
        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(plaintext_blocks) - 1):
            print("Encryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m",
                          i / len(plaintext_blocks),
                          "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(plaintext_blocks) - 1)) * len(cipher_obj.plaintext)))))



    # Return
    return ciphertext_blocks, key_one, key_two


# ECB mode. Straightforward decryption on each block. Nothing special
def decrypt_ecb(cipher_obj:Cipher, algorithm:Callable[[int],int], ciphertext_blocks:list, key_one:str,
                                                                    key_two:str) -> (list, str, str):
    """
    This runs a decryption in ECB mode.

    :param cipher_obj:        (Cipher)   The cipher object that is decrypting
    :param algorithm:         (Callable) The function that decrypts a block
    :param ciphertext_blocks: (list)     The int blocks to decrypts and decode
    :param key_one:           (str)      The key to read IV (nothing in this case)
    :param key_two:           (str)      Just for consistency's sake. Do nothing with this
    :return:                  (list)     The decrypted ciphertext_blocks
    :return:                  (str)      The key that was used
    :return:                  (str)      The private key that was used (if it exists)
    """


    plaintext_blocks = [0] * len(ciphertext_blocks)                # Build up the plaintext blocks here




    # Apply the block algorithm on each ciphertext block to get the plaintext block
    for i in range(0, len(ciphertext_blocks)):
        plaintext_blocks[i] = algorithm(ciphertext_blocks[i])
        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(ciphertext_blocks) - 1):
            print("Decryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m",
                          i / len(ciphertext_blocks),
                          "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(ciphertext_blocks) - 1)) * len(cipher_obj.ciphertext)))))


    # Return
    return plaintext_blocks, key_one, key_two







# CBC mode. XOR IV with first block and then encrypt. Successive blocks are XOR'd with previous encrypted block
def encrypt_cbc(cipher_obj:Cipher, algorithm:Callable[[int],int], plaintext_blocks:list, key_one:str,
                                                                key_two:str) ->(list, str, str):
    """
    CBC mode. XOR IV with first block and then encrypt. Successive blocks are XOR'd with previous encrypted block.
    Also, prepend keys with the character-encoded IV

    :param cipher_obj:       (Cipher)   The cipher object to get properties
    :param algorithm:        (Callable) The algorithm to use
    :param plaintext_blocks: (list)     The plaintext int blocks to encrypt
    :param key_one:          (str)      The key to prepend IV with
    :param key_two:          (str)      Another key to prepend IV with
    :return:                 (list)     The encrypted int block
    :return:                 (str)      The IV-prepended key
    :return:                 (str)      IV-prepended private key, if it exists
    """


    # Important instance vars for encryption
    block_size = cipher_obj.block_size
    encoding = cipher_obj.char_set


    # Build the ciphertext blocks here
    ciphertext_blocks = [0] * len(plaintext_blocks)


    # Generate an IV (and prepend it to keys)
    iv = secrets.randbits(block_size) ^ (1 << (block_size - 1))
    key_one = int_to_chars_encoding_scheme_pad(iv, encoding, block_size) + key_one
    key_two = int_to_chars_encoding_scheme_pad(iv, encoding, block_size) + key_two


    # XOR the first block with the IV. Save into ciphertext_blocks
    ciphertext_blocks[0] = algorithm( iv ^ plaintext_blocks[0] )



    # For all other blocks, XOR with previous encrypted block before applying algorithm
    for i in range(1, len(plaintext_blocks)):
        ciphertext_blocks[i] = algorithm( ciphertext_blocks[i - 1] ^ plaintext_blocks[i] )

        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(plaintext_blocks) - 1):
            print("Encryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m",
                          i / len(plaintext_blocks),
                          "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(plaintext_blocks) - 1)) * len(cipher_obj.plaintext)))))


    # Return ciphertext_blocks and the new keys
    return ciphertext_blocks, key_one, key_two



# CBC mode. Reverse the CBC
def decrypt_cbc(cipher_obj:Cipher, algorithm:Callable[[int],int], ciphertext_blocks:list, key_one:str,
                                                                key_two:str) -> (list, str, str):
    """
    Decrypt with CBC. Reverse what the encrypt did

    :param cipher_obj:        (Cipher)   The cipher object to get instance vars from
    :param algorithm:         (Callable) The algorithm to decrypt a block
    :param ciphertext_blocks: (list)     The encrypted integer blocks
    :param key_one:           (str)      The key to read IV from
    :param key_two:           (str)      Do nothing with this
    :return:                  (list)     The decrypted integer blocks
    :return:                  (str)      The symmetric/public key, not really used by caller
    :return:                  (str)      The private key, not really used by caller
    """

    # Important instance vars for decryption
    block_size = cipher_obj.block_size
    encoding = cipher_obj.char_set


    # Build the plaintext blocks here
    plaintext_blocks = [0] * len(ciphertext_blocks)


    # Read the IV. Generate random bits, and see how many characters to read
    iv_len = len(int_to_chars_encoding_scheme_pad(1, encoding, block_size))   # Encode block_size bits and get its len
    iv = chars_to_int_decoding_scheme(key_one[0 : iv_len], encoding)          # Get the integer form of the iv




    # Call algorithm on first ciphertext_block and XOR with iv
    plaintext_blocks[0] = algorithm(ciphertext_blocks[0]) ^ iv



    # For all successive blocks, call algorithm on ciphertext_block and XOR with the previous ciphertext_block
    for i in range(1, len(ciphertext_blocks)):
        plaintext_blocks[i] = algorithm(ciphertext_blocks[i]) ^ ciphertext_blocks[i - 1]

        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(ciphertext_blocks) - 1):
            print("Decryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m",
                          i / len(ciphertext_blocks),
                          "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(ciphertext_blocks) - 1)) * len(cipher_obj.ciphertext)))))


    # Return
    return plaintext_blocks, key_one, key_two









# PCBC mode. Similar to CBC, but xor previous ciphertext with the original plaintext before xor'ing with current block
def encrypt_pcbc(cipher_obj:Cipher, algorithm:Callable[[int],int], plaintext_blocks:list, key_one:str,
                                                                key_two:str) ->(list, str, str):
    """
    PCBC mode. Same as CBC, but XOR the previous ciphertext block with its original plaintext block before xor'ing
    with the current block before encrypting.

    :param cipher_obj:       (Cipher)   The cipher object to get properties
    :param algorithm:        (Callable) The algorithm to use
    :param plaintext_blocks: (list)     The plaintext int blocks to encrypt
    :param key_one:          (str)      The key to prepend IV with
    :param key_two:          (str)      Another key to prepend IV with
    :return:                 (list)     The encrypted int block
    :return:                 (str)      The IV-prepended key
    :return:                 (str)      IV-prepended private key, if it exists
    """


    # Important instance vars for encryption
    block_size = cipher_obj.block_size
    encoding = cipher_obj.char_set


    # Build the ciphertext blocks here
    ciphertext_blocks = [0] * len(plaintext_blocks)


    # Generate an IV (and prepend it to keys)
    iv = secrets.randbits(block_size) ^ (1 << (block_size - 1))
    key_one = int_to_chars_encoding_scheme_pad(iv, encoding, block_size) + key_one
    key_two = int_to_chars_encoding_scheme_pad(iv, encoding, block_size) + key_two


    # XOR the first block with the IV. Save into ciphertext_blocks
    ciphertext_blocks[0] = algorithm( iv ^ plaintext_blocks[0] )



    # For all other blocks, XOR with previous encrypted block before applying algorithm
    for i in range(1, len(plaintext_blocks)):
        ciphertext_blocks[i] = algorithm( (plaintext_blocks[i - 1] ^ ciphertext_blocks[i - 1]) ^ plaintext_blocks[i] )

        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(plaintext_blocks) - 1):
            print("Encryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m",
                          i / len(plaintext_blocks),
                          "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(plaintext_blocks) - 1)) * len(cipher_obj.plaintext)))))


    # Return ciphertext_blocks and the new keys
    return ciphertext_blocks, key_one, key_two


# PCBC mode. Reverse the PCBC
def decrypt_pcbc(cipher_obj:Cipher, algorithm:Callable[[int],int], ciphertext_blocks:list, key_one:str,
                                                                key_two:str) -> (list, str, str):
    """
    Decrypt with PCBC. Reverse what the encrypt did

    :param cipher_obj:        (Cipher)   The cipher object to get instance vars from
    :param algorithm:         (Callable) The algorithm to decrypt a block
    :param ciphertext_blocks: (list)     The encrypted integer blocks
    :param key_one:           (str)      The key to read IV from
    :param key_two:           (str)      Do nothing with this
    :return:                  (list)     The decrypted integer blocks
    :return:                  (str)      The symmetric/public key, not really used by caller
    :return:                  (str)      The private key, not really used by caller
    """

    # Important instance vars for decryption
    block_size = cipher_obj.block_size
    encoding = cipher_obj.char_set


    # Build the plaintext blocks here
    plaintext_blocks = [0] * len(ciphertext_blocks)


    # Read the IV. Generate random bits, and see how many characters to read
    iv_len = len(int_to_chars_encoding_scheme_pad(1, encoding, block_size))   # Encode block_size bits and get its len
    iv = chars_to_int_decoding_scheme(key_one[0 : iv_len], encoding)          # Get the integer form of the iv




    # Call algorithm on first ciphertext_block and XOR with iv
    plaintext_blocks[0] = algorithm(ciphertext_blocks[0]) ^ iv



    # For all successive blocks, call algorithm on ciphertext_block and XOR with the previous ciphertext_block
    for i in range(1, len(ciphertext_blocks)):
        plaintext_blocks[i] = algorithm(ciphertext_blocks[i]) ^ (ciphertext_blocks[i - 1] ^ plaintext_blocks[i - 1])

        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(ciphertext_blocks) - 1):
            print("Decryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m",
                          i / len(ciphertext_blocks),
                          "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(ciphertext_blocks) - 1)) * len(cipher_obj.ciphertext)))))


    # Return
    return plaintext_blocks, key_one, key_two










# CFB mode. Similar to CBC, but encrypt iv instead of the plaintext block. XOR iv encrypted result with plaintext block
def encrypt_cfb(cipher_obj:Cipher, algorithm:Callable[[int],int], plaintext_blocks:list, key_one:str,
                                                                key_two:str) ->(list, str, str):
    """
    CFB mode. Similar to CBC, but encrypt the iv instead of the plaintext block. XOR the iv encrypted result with the
    plaintext block. For successive plaintext blocks, encrypt the previous ciphertext block and XOR with the current
    plaintext block.

    :param cipher_obj:       (Cipher)   The cipher object to get properties
    :param algorithm:        (Callable) The algorithm to use
    :param plaintext_blocks: (list)     The plaintext int blocks to encrypt
    :param key_one:          (str)      The key to prepend IV with
    :param key_two:          (str)      Another key to prepend IV with
    :return:                 (list)     The encrypted int block
    :return:                 (str)      The IV-prepended key
    :return:                 (str)      IV-prepended private key, if it exists
    """


    # Important instance vars for encryption
    block_size = cipher_obj.block_size
    encoding = cipher_obj.char_set


    # Build the ciphertext blocks here
    ciphertext_blocks = [0] * len(plaintext_blocks)


    # Generate an IV (and prepend it to keys)
    iv = secrets.randbits(block_size) ^ (1 << (block_size - 1))
    key_one = int_to_chars_encoding_scheme_pad(iv, encoding, block_size) + key_one
    key_two = int_to_chars_encoding_scheme_pad(iv, encoding, block_size) + key_two


    # XOR the first block with the IV. Save into ciphertext_blocks
    ciphertext_blocks[0] = algorithm(iv) ^ plaintext_blocks[0]



    # For all other blocks, encrypt the previous ciphertext_block and XOR with the current one
    for i in range(1, len(plaintext_blocks)):
        ciphertext_blocks[i] = algorithm( ciphertext_blocks[i - 1] ) ^ plaintext_blocks[i]



        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(plaintext_blocks) - 1):
            print("Encryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m", i / len(plaintext_blocks), "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(plaintext_blocks) - 1)) * len(cipher_obj.plaintext)))))


    # Return ciphertext_blocks and the new keys
    return ciphertext_blocks, key_one, key_two


# CFB mode. Reverse the PCBC
def decrypt_cfb(cipher_obj:Cipher, algorithm:Callable[[int],int], ciphertext_blocks:list, key_one:str,
                                                                key_two:str) -> (list, str, str):
    """
    Decrypt with OFB. Almost identical to CBC encryption, but done in reverse.

    :param cipher_obj:        (Cipher)   The cipher object to get instance vars from
    :param algorithm:         (Callable) The algorithm to decrypt a block
    :param ciphertext_blocks: (list)     The encrypted integer blocks
    :param key_one:           (str)      The key to read IV from
    :param key_two:           (str)      Do nothing with this
    :return:                  (list)     The decrypted integer blocks
    :return:                  (str)      The symmetric/public key, not really used by caller
    :return:                  (str)      The private key, not really used by caller
    """

    # Important instance vars for decryption
    block_size = cipher_obj.block_size
    encoding = cipher_obj.char_set


    # Build the plaintext blocks here
    plaintext_blocks = [0] * len(ciphertext_blocks)


    # Read the IV. Generate random bits, and see how many characters to read
    iv_len = len(int_to_chars_encoding_scheme_pad(1, encoding, block_size))   # Encode block_size bits and get its len
    iv = chars_to_int_decoding_scheme(key_one[0 : iv_len], encoding)          # Get the integer form of the iv




    # Call algorithm on first ciphertext_block and XOR with iv
    plaintext_blocks[0] = algorithm(iv) ^ ciphertext_blocks[0]



    # For all successive blocks, call algorithm on ciphertext_block and XOR with the previous ciphertext_block
    for i in range(1, len(ciphertext_blocks)):
        plaintext_blocks[i] = algorithm(ciphertext_blocks[i - 1]) ^ ciphertext_blocks[i]


        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(ciphertext_blocks) - 1):
            print("Decryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m",
                          i / len(ciphertext_blocks),
                          "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(ciphertext_blocks) - 1)) * len(cipher_obj.ciphertext)))))


    # Return
    return plaintext_blocks, key_one, key_two









# OFB mode. It generates keystream blocks, which are XOR'ed with plaintext blocks to get ciphertext blocks
def encrypt_ofb(cipher_obj:Cipher, algorithm:Callable[[int],int], plaintext_blocks:list, key_one:str,
                                                                key_two:str) ->(list, str, str):
    """
    OFB mode. Similar to CBC, but encrypt the iv instead of the plaintext block. XOR the iv encrypted result with the
    plaintext block. For successive plaintext blocks, encrypt the previous ciphertext block and XOR with the current
    plaintext block.

    :param cipher_obj:       (Cipher)   The cipher object to get properties
    :param algorithm:        (Callable) The algorithm to use
    :param plaintext_blocks: (list)     The plaintext int blocks to encrypt
    :param key_one:          (str)      The key to prepend IV with
    :param key_two:          (str)      Another key to prepend IV with
    :return:                 (list)     The encrypted int block
    :return:                 (str)      The IV-prepended key
    :return:                 (str)      IV-prepended private key, if it exists
    """


    # Important instance vars for encryption
    block_size = cipher_obj.block_size
    encoding = cipher_obj.char_set


    # Build the ciphertext blocks here
    ciphertext_blocks = [0] * len(plaintext_blocks)


    # Generate an IV (and prepend it to keys)
    iv = secrets.randbits(block_size) ^ (1 << (block_size - 1))
    key_one = int_to_chars_encoding_scheme_pad(iv, encoding, block_size) + key_one
    key_two = int_to_chars_encoding_scheme_pad(iv, encoding, block_size) + key_two


    # XOR the first block with the IV. Save into ciphertext_blocks
    ciphertext_blocks[0] = algorithm(iv) ^ plaintext_blocks[0]
    algorithm_output = algorithm(iv)


    # For all other blocks, XOR with previous encrypted block before applying algorithm
    for i in range(1, len(plaintext_blocks)):
        ciphertext_blocks[i] = algorithm( algorithm_output ) ^ plaintext_blocks[i]
        algorithm_output = algorithm(algorithm_output)


        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(plaintext_blocks) - 1):
            print("Encryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m", i / len(plaintext_blocks), "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(plaintext_blocks) - 1)) * len(cipher_obj.plaintext)))))


    # Return ciphertext_blocks and the new keys
    return ciphertext_blocks, key_one, key_two


# OFB mode. Exactly the same as the encrypt
def decrypt_ofb(cipher_obj:Cipher, algorithm:Callable[[int],int], ciphertext_blocks:list, key_one:str,
                                                                key_two:str) -> (list, str, str):
    """
    Decrypt with OFB. Reverse what the encrypt did.

    :param cipher_obj:        (Cipher)   The cipher object to get instance vars from
    :param algorithm:         (Callable) The algorithm to decrypt a block
    :param ciphertext_blocks: (list)     The encrypted integer blocks
    :param key_one:           (str)      The key to read IV from
    :param key_two:           (str)      Do nothing with this
    :return:                  (list)     The decrypted integer blocks
    :return:                  (str)      The symmetric/public key, not really used by caller
    :return:                  (str)      The private key, not really used by caller
    """

    # Important instance vars for decryption
    block_size = cipher_obj.block_size
    encoding = cipher_obj.char_set


    # Build the plaintext blocks here
    plaintext_blocks = [0] * len(ciphertext_blocks)


    # Read the IV. Generate random bits, and see how many characters to read
    iv_len = len(int_to_chars_encoding_scheme_pad(1, encoding, block_size))   # Encode block_size bits and get its len
    iv = chars_to_int_decoding_scheme(key_one[0 : iv_len], encoding)          # Get the integer form of the iv




    # Call algorithm on first ciphertext_block and XOR with iv
    plaintext_blocks[0] = algorithm(iv) ^ ciphertext_blocks[0]
    algorithm_output = algorithm(iv)


    # For all successive blocks, call algorithm on ciphertext_block and XOR with the previous ciphertext_block
    for i in range(1, len(ciphertext_blocks)):
        plaintext_blocks[i] = algorithm(algorithm_output) ^ ciphertext_blocks[i]
        algorithm_output = algorithm(algorithm_output)

        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(ciphertext_blocks) - 1):
            print("Decryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m",
                          i / len(ciphertext_blocks),
                          "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(ciphertext_blocks) - 1)) * len(cipher_obj.ciphertext)))))


    # Return
    return plaintext_blocks, key_one, key_two







# CTR mode. It encrypts an iv and a counter, and XORs the result with the plaintext
def encrypt_ctr(cipher_obj:Cipher, algorithm:Callable[[int],int], plaintext_blocks:list, key_one:str,
                                                                key_two:str) ->(list, str, str):
    """
    CTR mode. It encrypts with a block, the upper bits being the IV, and the lower bits being the counter. The result of
    the encryption is XOR'ed with the plaintext block.

    :param cipher_obj:       (Cipher)   The cipher object to get properties
    :param algorithm:        (Callable) The algorithm to use
    :param plaintext_blocks: (list)     The plaintext int blocks to encrypt
    :param key_one:          (str)      The key to prepend IV with
    :param key_two:          (str)      Another key to prepend IV with
    :return:                 (list)     The encrypted int block
    :return:                 (str)      The IV-prepended key
    :return:                 (str)      IV-prepended private key, if it exists
    """


    # Important instance vars for encryption
    block_size = cipher_obj.block_size
    encoding = cipher_obj.char_set


    # Build the ciphertext blocks here
    ciphertext_blocks = [0] * len(plaintext_blocks)


    # Generate an IV (and prepend it to keys). IV is half the size of the block (will be upper bits so shift)
    iv = secrets.randbits(block_size // 2) ^ (1 << ((block_size // 2) - 1))         # IV is half the block (round down)
    iv = iv << int(math.ceil(block_size / 2))                                       # Shift to upper bits (round up)
    key_one = int_to_chars_encoding_scheme_pad(iv, encoding, block_size) + key_one
    key_two = int_to_chars_encoding_scheme_pad(iv, encoding, block_size) + key_two


    # Encrypt with nonce/counter, and XOR with the plaintext block
    ciphertext_blocks[0] = algorithm(iv ^ 0) ^ plaintext_blocks[0]



    # For all other blocks, XOR with previous encrypted block before applying algorithm
    for i in range(1, len(plaintext_blocks)):
        ciphertext_blocks[i] = algorithm( iv ^ i ) ^ plaintext_blocks[i]



        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(plaintext_blocks) - 1):
            print("Encryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m", i / len(plaintext_blocks), "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(plaintext_blocks) - 1)) * len(cipher_obj.plaintext)))))


    # Return ciphertext_blocks and the new keys
    return ciphertext_blocks, key_one, key_two


# CTR mode. Same as encrypt, but switch plaintext_block and ciphertext_block
def decrypt_ctr(cipher_obj:Cipher, algorithm:Callable[[int],int], ciphertext_blocks:list, key_one:str,
                                                                key_two:str) -> (list, str, str):
    """
    Decrypt with CTR. Same as encrypt, but switch plaintext_block and ciphertext_block

    :param cipher_obj:        (Cipher)   The cipher object to get instance vars from
    :param algorithm:         (Callable) The algorithm to decrypt a block
    :param ciphertext_blocks: (list)     The encrypted integer blocks
    :param key_one:           (str)      The key to read IV from
    :param key_two:           (str)      Do nothing with this
    :return:                  (list)     The decrypted integer blocks
    :return:                  (str)      The symmetric/public key, not really used by caller
    :return:                  (str)      The private key, not really used by caller
    """

    # Important instance vars for decryption
    block_size = cipher_obj.block_size
    encoding = cipher_obj.char_set


    # Build the plaintext blocks here
    plaintext_blocks = [0] * len(ciphertext_blocks)


    # Read the IV. Generate random bits, and see how many characters to read
    iv_len = len(int_to_chars_encoding_scheme_pad(1, encoding, block_size))   # Encode block_size bits and get its len
    iv = chars_to_int_decoding_scheme(key_one[0 : iv_len], encoding)          # Get the integer form of the iv



    # Call algorithm on first ciphertext_block and XOR with iv
    plaintext_blocks[0] = algorithm(iv ^ 0) ^ ciphertext_blocks[0]



    # For all successive blocks, call algorithm on ciphertext_block and XOR with the previous ciphertext_block
    for i in range(1, len(ciphertext_blocks)):
        plaintext_blocks[i] = algorithm(iv ^ i) ^ ciphertext_blocks[i]


        if i % (utf_8_to_int_blocks.update_interval / 1) == 0 or i == (len(ciphertext_blocks) - 1):
            print("Decryption percent done: {}{:.2%}{} with {} characters"
                  .format("\u001b[32m",
                          i / len(ciphertext_blocks),
                          "\u001b[0m",
                          "{:,}".format(int(safe_div(i, (len(ciphertext_blocks) - 1)) * len(cipher_obj.ciphertext)))))


    # Return
    return plaintext_blocks, key_one, key_two





























