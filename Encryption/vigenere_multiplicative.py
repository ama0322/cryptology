import miscellaneous










def execute(data, output_location):
    """
    This function calls the appropriate functions in miscellaneous.py. Those functions will use the encrypt() function
    located below as the algorithm to actually encrypt the text. Then, the ciphertext will be returned back to
    cryptography_runner.py

    :param data: (string) the data to be encrypted
    :param output_location: (string) the file to write relevant information into
    :return: (string) the encrypted data
    """


    # Encrypt the plaintext. Print out the ciphertext and relevant information
    miscellaneous.execute_encryption_or_decryption(data, output_location,
                                                   "Encryption", "vigenere_multiplicative", "encrypt")





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

    ciphertext = "" # The string used to build up the encrypted text, one character at a time
    key_index = 0 # This indicates the index of the key that the vigenere cipher is currently on
    counter = 0 # To print regular updates

    # Adjust the char set size to exclude surrogates
    if char_set_size > 256:
        char_set_size -= miscellaneous.SURROGATE_BOUND_LENGTH



    # For each character in plaintext
    for x in plaintext:

        # Print updates (every 1000 characters)
        if counter % 1000 == 0:
            print("ENCRYPTION\tPercent of text done: "
                    + str((counter / len(plaintext)) * 100) + "%")
        counter += 1


        # Obtain the two unicode values to operate on
        uni_val_plain = ord(x)                                 # Find unicode value of plaintext char
        key_char = key[key_index]                               # Figure out which character to use
        uni_val_key = ord(key_char)                             # Find unicode value of the key
        key_index = (key_index + 1) % len(key)                  # Update key index for next iteration


        # Figure out the uni_val_cipher. Do NOT adjust for surrogates yet.
        uni_val_encrypted = (uni_val_plain * uni_val_key) % char_set_size

        # Obtain the number of overlaps that come before this one(this uni_val_plain) and NOT including this one
        overlap_counter = 0;
        for i in range(0, 1114112):

            # If it is an overlap character
            if (i * uni_val_key) % char_set_size  == uni_val_encrypted and i != uni_val_plain:
                overlap_counter += 1
                continue

            # If it is the actual character
            elif i == uni_val_plain:
                break




        # Adjust the uni_val_encrypted to fit outside the surrogates if necessary
        if miscellaneous.SURROGATE_LOWER_BOUND <= uni_val_encrypted:
            uni_val_encrypted = uni_val_encrypted + miscellaneous.SURROGATE_BOUND_LENGTH



        #  figure out the character corresponding to the unicode value, and add to the ciphertext
        encrypted_char = chr(uni_val_encrypted)
        ciphertext = ciphertext + encrypted_char + str(overlap_counter) + " "




    return ciphertext





