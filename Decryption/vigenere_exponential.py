import miscellaneous
import time
#from decimal import * #  use exact decimals to calculate nth roots
#getcontext().prec = 3 #  not much precision is necessary







def execute(data, output_location):
    """
    This function decrypts data using a key.

    :param data: the data to be decrypted
    :return: the decrypted data
    """

    # Obtain the decrypted text. Also write statistics and relevant info to a file
    decrypted = miscellaneous.encrypt_or_decrypt_with_general_key(data, output_location,
                                                             "Decryption", "vigenere_exponential", "decrypt")


    # Return encrypted text to be written in cryptography_runner
    return decrypted





# The testing form of execute
def testing_execute(cipher_text, output_location, plain_text, key, char_set_size, encryption_time):
    """
    Decrypt and save statistics.

    :param cipher_text: (string) the encrypted text to decipher
    :param output_location: (string) the file to save statistics into
    :param plain_text: (string) the original plain text
    :param key: (string) the key used to decrypt
    :param char_set_size: (integer) the character set used
    :param encryption_time: (double) the time it took to encrypt using vigenere
    :return: None
    """

    # Run the decryption algorithm on the cipher_text
    start_time = time.time()
    decrypted = decrypt(cipher_text, key, char_set_size)
    decryption_time = time.time() - start_time

    # Open file for writing
    new_file = open(output_location, "w", encoding="utf-8")

    # Set up a space for notes
    if decrypted == plain_text:
        new_file.writelines(["Vigenere_Exponential\nCORRECT \n\n\nNotes: "])
    else:
        # Calculate the number of characters that differ
        count = sum(1 for a, b in zip(decrypted, plain_text) if a != b)
        new_file.writelines(["Vigenere_Exponential" + "\nINCORRECT"
                             + "\tDiffering characters: " + str(count)
                             + "\tPercentage difference: " + str((count / len(plain_text)) * 100) + "\n\n\nNotes: "])


    # Encryption information
    new_file.writelines(["\n\n\nEncryptionEncryptionEncryptionEncryptionEncryptionEncryptionEncryptionEncryption",
                         "\nThe key is: " + key,
                         "\nEncrypted in: " + str(encryption_time) + " seconds.",
                         "\nThat is " + str(encryption_time / len(decrypted)) + " seconds per character.",
                         "\nThat is " + str((encryption_time / len(decrypted) * 1000000))
                         + " microseconds per character."])

    # Decryption information
    new_file.writelines(["\n\n\nDecryptionDecryptionDecryptionDecryptionDecryptionDecryptionDecryptionDecryption",
                         "\nThe character set is : " + [char_set for char_set,
                                                                     value in
                                                        miscellaneous.char_set_to_char_set_size.items()
                                                        if value == char_set_size][0],
                         "\nThe key is: " + key,
                         "\nDecrypted in: " + str(decryption_time) + " seconds.",
                         "\nThat is " + str(encryption_time / len(decrypted)) + " seconds per character.",
                         "\nThat is " + str((decryption_time / len(decrypted) * 1000000))
                         + " microseconds per character."])

    # Print out the cipher_text
    new_file.writelines(["\n\n\nCipher text: \n" + cipher_text])

    # Print out the decrypted
    new_file.writelines(["\n\n\nDecrypted text: \n" + decrypted])

    # Print out the plain_text
    new_file.writelines(["\n\n\nPlain text: \n" + plain_text])

    new_file.close()







# Contains the actual algorithm to decrypt with vigenere_exponential cipher
def decrypt(cipher_text, key, char_set_size):
    """
    This function decrypts with vigenere. Instead of exponents, take the nth root.

    :param cipher_text: (string) the cipher text to decrypt
    :param key: (string) the string to decrypt with
    :param char_set_size: (int) the size of the character set used
    :return: (string) the deciphered text
    """

    plain_text = ""
    key_index = 0

    # Adjust the char set size to exclude surrogates
    if char_set_size > 256:
        char_set_size -= miscellaneous.SURROGATE_BOUND_LENGTH


    counter = 0
    for x in cipher_text:


        # Print updates (every 1000 characters)
        if counter % 1000 == 0:
            print("DECRYPTION\tPercent of text done: " + str(counter / len(cipher_text) * 100) )


        #  figure out the unicode value for each of the characters(reverse surrogate adjustment in encryption if needed)
        uni_val_cipher = ord(x)
        if uni_val_cipher >= miscellaneous.SURROGATE_LOWER_BOUND:
            uni_val_cipher = uni_val_cipher - miscellaneous.SURROGATE_BOUND_LENGTH


        #  figure out the unicode value for the right character in the key, then update for next iteration
        key_char = key[key_index]
        uni_val_key = ord(key_char)
        key_index = (key_index + 1) % len(key)


        #  find original plain char by taking all possibilities (y) and raising that to uni_val_keyth power for match
        def _find_plain_char(uni_val_key, char_set_size, uni_val_cipher, counter):

            # TRY THE SPACE FIRST
            if (32 ** uni_val_key) % char_set_size == uni_val_cipher:
                return chr(32), counter + 1

            # TRY LOWERCASE LETTERS
            for y in range(97, 123):
                # If mod_result equal to unicode value of cipher, correct plain unicode value haas been found.
                if (y ** uni_val_key) % char_set_size == uni_val_cipher:
                    return chr(y), counter + 1

            # TRY UPPERCASE LETTERS
            for y in range(65, 91):
                # If mod_result equal to unicode value of cipher, correct plain unicode value haas been found.
                if (y ** uni_val_key) % char_set_size == uni_val_cipher:
                    return chr(y), counter + 1

            # TRY THE OTHER PRINTABLES
            for y in range(32, 128):
                # If mod_result equal to unicode value of cipher, correct plain unicode value haas been found.
                if (y ** uni_val_key) % char_set_size == uni_val_cipher:
                    return chr(y), counter + 1

            # TRY EVERYTHING ELSE (except null)
            for y in range(1, 32):
                # If mod_result equal to unicode value of cipher, correct plain unicode value haas been found.
                if (y ** uni_val_key) % char_set_size == uni_val_cipher:
                    return chr(y), counter + 1

            # Nothing else, so return null
            return chr(0), counter + 1
        plain_char, counter = _find_plain_char(uni_val_key, char_set_size, uni_val_cipher, counter)


        # Add plain char to the plain text
        plain_text += plain_char
    # END OF LOOP TO BUILD UP THE CIPHER_TEXT


    return plain_text







