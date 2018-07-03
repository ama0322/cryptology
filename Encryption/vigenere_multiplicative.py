import miscellaneous
import time









def execute(data, output_location):
    """
    This function calls the appropriate functions in miscellaneous.py. Those functions will use the encrypt() function
    located below as the algorithm to actually encrypt the text. Then, the ciphertext will be returned back to
    cryptography_runner.py

    :param data: (string) the data to be encrypted
    :param output_location: (string) the file to write relevant information into
    :return: (string) the encrypted data
    """


    # Obtain the encrypted text. Also write statistics and relevant info a file
    encrypted = miscellaneous.symmetric_encrypt_or_decrypt_with_general_key(data, output_location,
                                                                  "Encryption", "vigenere_multiplicative", "encrypt")

    # Return encrypted text to be written in cryptography_runner
    return encrypted





# The actual algorithm to encrypt using a vigenere cipher(multiplication instead of addition)
def encrypt(plaintext, key, char_set_size):
    """
    This function encrypts with a vigenere cipher that multiplies instead of adds. Done to access more characters in
    unicode. If ascii or extended_ascii, store as numbers. Otherwise, store as characters

    :param plaintext: (string) the plaintext to encrypt with
    :param key: (string) the string to encrypt with
    :param char_set_size: (integer) the number of characters in the character set used
    :return: (string) the encrypted text
    """

    ciphertext = ""
    ciphertext_list = [] # for storing unicode values of the numbers (when char_set_size <= 256). Done for speed
    key_index = 0

    # if using unicode, then adjust the size of the char_set_size to be printable characters only (no surrogates)
    if char_set_size > 256:
        char_set_size = char_set_size - miscellaneous.SURROGATE_BOUND_LENGTH

    # Counter for printing purposes
    characters_done = 0

    for x in plaintext:

        characters_done += 1

        #  figure out the unicode value for each of the characters
        uni_val_plain = ord(x)

        #  figure out the unicode value for the right character in the key, then update for next iteration
        key_char = key[key_index]
        uni_val_key = ord(key_char)

        key_index = (key_index + 1) % len(key)


        # figure out the encrypted character val (un-modded)
        uni_val_encrypted = (uni_val_plain * uni_val_key)


        #  if the encrypted_char would be a surrogate(unprintable), adjust by adding SURROGATE_BOUND_LENGTH
        if miscellaneous.SURROGATE_LOWER_BOUND <= uni_val_encrypted:
            encrypted_char = chr(uni_val_encrypted + miscellaneous.SURROGATE_BOUND_LENGTH)


        # Print updates
        if characters_done % 100 == 0:
            print ("Percentage of text done: " + str(characters_done / len(plaintext) * 100))


        #  Add the encrypted character to the overall encrypted message (if using unicode)
        if char_set_size > 256:

            # Find the encrypted char value(modded)
            uni_val_encrypted = (uni_val_plain * uni_val_key) % char_set_size
            encrypted_char = chr(uni_val_encrypted)

            # Add to ciphertext
            ciphertext = ciphertext + encrypted_char

        # Otherwise, add the number to the overall encrypted message (list)
        else:
            ciphertext_list.append(str(uni_val_encrypted))


    # Build up ciphertext if necessary(when we were using list (when char_set_size <= 256))
    if ciphertext == "":
        ciphertext = " ".join(ciphertext_list)

    return ciphertext





