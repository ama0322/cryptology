




import copy            # To make deep-copies
import time            # To time various processes






################################################################################################### RESOURCES ##########

# Sets containing available options for decryption and encryption. Add to this.
DECRYPTION_SET = {"rotation"}
ENCRYPTION_SET = {"rotation"}



# The characters used for more classical-type ciphers, along with the sizes
ALPHABETS = {"ascii":128 , "extended_ascii":256, "unicode_plane0":65536, "unicode":1114112}
# Unprintable characters in unicode/unicode_plane0
SURROGATE_LOWER_BOUND  = 55296              # inclusive
SURROGATE_UPPER_BOUND  = 57343              # inclusive
SURROGATE_BOUND_LENGTH = 57343 - 55296 + 1  # equal to 2048

# Encoding schemes (completely random bits to characters)
ENCODING_SCHEMES = {"base16":16, "base32":32, "base64":64, "base85":85, "ascii":128, "extended_ascii":256,
                    "base4096":4096}



# Modes of encryptions
MODES_OF_ENCRYPTION = ["ecb", "cbc"]






########################################################################################### USEFUL ALGORITHMS ##########

########## MISCELLANEOUS ##########
# This decorator gives static vars (**kwargs) to the decorated function. Parameters: (static_one=1, static_two=2, ...)
def static_vars(**kwargs):
    def decorate(function_to_decorate):
        for k in kwargs:
            setattr(function_to_decorate, k, kwargs[k])
        return function_to_decorate
    return decorate

# This decorator returns the time it takes for the decorated function to run
def time_this(function_to_decorate) -> float:

    start_time = time.time()
    function_to_decorate()
    return time.time() - start_time + 0.00000000000000001         # Prevent the time from being 0.0







# Figure out the character set of the given data automatically if possible
@static_vars(short_text_len=300)
def calculate_char_set_of(data: str, cipher_char_set: str, is_ciphertext:bool) -> str:
    """
    This calculates the character set of the given data. If the text given is ciphertext, then the user will be
    prompted to manually enter in the char_set for short texts. Otherwise, if the text given is plaintext,
    then figure it out automatically.

    :param data:            (str)  The data to analyze for char_set
    :param cipher_char_set: (str)  Either "alphabet" or "encoding scheme"
    :param is_ciphertext:   (bool) Indicates whether or not it is ciphertext
    :return:                (str)  The name of the char_set that the data is in
    """

    # Ciphertext ata too short. Must manually ask user for the character set
    if is_ciphertext and len(data) <= calculate_char_set_of.short_text_len:

        # Ask for the user input
        user_choice = input("Ciphertext with %d characters is too short to accurately determine its %s. "
                            "Manually enter the %s: " % (len(data), cipher_char_set, cipher_char_set))

        # While the user's choice is invalid, keep looping. Break when user entry is valid
        while True:

            # If valid alphabet
            if cipher_char_set == "alphabet" and user_choice in ALPHABETS:
                break

            # If valid encoding scheme
            if cipher_char_set == "encoding scheme" and user_choice in ENCODING_SCHEMES:
                break

            # Invalid choice, ask for another input
            user_choice = input("\"%s\" is not a valid %s! Try again: " % (user_choice, cipher_char_set))

        return user_choice



    # Data is long enough or is plaintext, figure it out automatically
    else:
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




# Adjust the alphabet if necessary
def adjust_alphabet(data: str, alphabet: str, cipher_char_set: str, restrict_alphabet: bool) -> str:
    """
    Some ciphers cannot work correctly if the chosen ciphertext alphabet is smaller than the plaintext's alphabet.
    They require at minimum the plaintext's alphabet to decrypt correctly. So switch to use the plaintext's alphabet
    for encryption, and inform the user.

    :param data:              (str)  The text
    :param alphabet:          (str)  The selected alphabet. Needs to be checked
    :param cipher_char_set:   (str)  Either "alphabet" or "encoding scheme"
    :param restrict_alphabet: (bool) indicates whether restricting (adjusting) the alphabet is necessary
    :return:
    """


    if restrict_alphabet == False:  # If alphabet restriction not necessary, just return
        return alphabet

    # Figure out the "true" alphabet of the plaintext.
    original_short_len = copy.deepcopy(calculate_char_set_of.short_text_len)
    calculate_char_set_of.short_text_len = -1
    true_alphabet = calculate_char_set_of(data, cipher_char_set, False)
    calculate_char_set_of.short_text_len = original_short_len

    # If the "true alphabet" is larger than the chosen alphabet, then inform user automatically switch
    if ALPHABETS.get(true_alphabet) > ALPHABETS.get(alphabet):
        print("The chosen alphabet for encryption \"%s\" is insufficient for the alphabet that the plaintext is in. "
              "Therefore, the alphabet for encryption is switched to: \"%s\"" % (alphabet, true_alphabet))
        return true_alphabet

    # Otherwise, all clear, return the user-selected alphabet
    else:
        return alphabet












