import miscellaneous
import time # For writing relevant information









# Call the proper functions to decrypt. Return decrypted text back to cryptography_runner.py
def execute(data, output_location):
    """
    This function decrypts data using a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the file to write relevant information into
    :return: (string) the decrypted data
    """


    # Obtain the decrypted text. Also write statistics and relevant info to a file
    decrypted = miscellaneous.symmetric_encrypt_or_decrypt_with_general_key(data, output_location,
                                                             "Decryption", "vigenere_multiplicative", "decrypt")


    # Return encrypted text to be written in cryptography_runner
    return decrypted




# The testing form of execute
def testing_execute(ciphertext, output_location, plaintext, key, char_set_size, encryption_time):
    """
    Decrypt and save statistics.

    :param ciphertext: (string) the encrypted text to decipher
    :param output_location: (string) the file to save statistics into
    :param plaintext: (string) the original plaintext
    :param key: (string) the key used to decrypt
    :param char_set_size: (integer) the character set used
    :param encryption_time: (double) the time it took to encrypt using vigenere
    :return: None
    """

    # Run the decryption algorithm on the ciphertext
    start_time = time.time()
    decrypted = decrypt(ciphertext, key, char_set_size)
    decryption_time = time.time() - start_time

    # Open file for writing
    new_file = open(output_location, "w", encoding="utf-8")

    # Set up a space for notes
    if decrypted == plaintext:
        new_file.writelines(["Vigenere_Multiplicative\nCORRECT \n\n\nNotes: "])
        print("Vignere Multiplicative: CORRECT\n")
    else:
        # Calculate the number of characters that differ
        count = sum(1 for a, b in zip(decrypted, plaintext) if a != b)
        new_file.writelines(["Vigenere_Multiplicative" + "\nINCORRECT"
                             + "\tDiffering characters: " + str(count)
                             + "\tPercentage difference: " + str((count / len(plaintext)) * 100) + "\n\n\nNotes: "])
        print("Vigenere Multiplicative: INCORRECT\n")

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

    # Print out the ciphertext
    new_file.writelines(["\n\n\nciphertext: \n" + ciphertext])

    # Print out the decrypted
    new_file.writelines(["\n\n\nDecrypted text: \n" + decrypted])

    # Print out the plaintext
    new_file.writelines(["\n\n\nplaintext: \n" + plaintext])

    new_file.close()




# Contains the actual algorithm to decrypt with vigenere_multiplicative cipher
def decrypt(ciphertext, key, char_set_size):
    """
    This function decrypts with vigenere. Instead of multiplying, divide. Read as numbers if char_set_size <=256.
    Otherwise, read as characters

    :param ciphertext: (string) the ciphertext to decrypt
    :param key: (string) the string to decrypt with
    :param char_set_size: (int) the size of the character set used
    :return: (string) the deciphered text
    """


    plaintext = ""
    key_index = 0

    # if using unicode, then adjust the size of the char_set_size to be printable characters only
    if char_set_size > 256:
        char_set_size = char_set_size - miscellaneous.SURROGATE_BOUND_LENGTH



    # Read and decrypt the ciphertext if it is numbers, not characters (char_set_size <= 256)
    if char_set_size <= 256:

        # Obtain a list of the numbers in the ciphertext
        numbers = ciphertext.split(" ")
        for x in range(0, len(numbers)):
            numbers[x] = int(float(numbers[x]))

        # Decrypt each character in the ciphertext
        for i in numbers:

            # The unicode value of plain is the cipher number divided by the unival of the right index of the key
            uni_val_plain = i // ord(key[key_index])
            key_index = (key_index + 1 ) % len(key)

            # Add the unicode character of this unicode value to the plaintext
            plaintext = plaintext + chr(uni_val_plain)


    # Else, read and decrypt eh ciphertext as characters (char_set_size > 256)
    else:

        for x in ciphertext:

            # figure out the unicode value for each of the characters
            uni_val_cipher = ord(x)

            # Figure out the unicode value for the irght character in the key. Then update for next iteration
            uni_val_key = ord(key[key_index])
            key_index = (key_index + 1) % len(key)

            # Adjust for surrogates if necessary by subtracting SURROGATE_BOUND_LENGTH
            if miscellaneous.SURROGATE_LOWER_BOUND <= uni_val_cipher:
                uni_val_cipher = uni_val_cipher - miscellaneous.SURROGATE_BOUND_LENGTH

            # Figure out the decrypted character value(should be int by default)
            uni_val_decrypted = int(uni_val_cipher // uni_val_key)
            decrypted_char = chr(uni_val_decrypted)

            # Add this character to the plaintext
            plaintext = plaintext + decrypted_char


    # Finished, so return the decrypted text
    return plaintext











