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
    decrypted = miscellaneous.symmetric_encrypt_or_decrypt_with_general_key(data, output_location,
                                                             "Decryption", "vigenere_exponential", "decrypt")


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
        new_file.writelines(["Vigenere_Exponential\nCORRECT \n\n\nNotes: "])
        print("Vigenere Exponential: CORRECT\n")
    else:
        # Calculate the number of characters that differ
        count = sum(1 for a, b in zip(decrypted, plaintext) if a != b)
        new_file.writelines(["Vigenere_Exponential" + "\nINCORRECT"
                             + "\tDiffering characters: " + str(count)
                             + "\tPercentage difference: " + str((count / len(plaintext)) * 100) + "\n\n\nNotes: "])
        print("Vignere Exponential: INCORRECT\n")


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







# Contains the actual algorithm to decrypt with vigenere_exponential cipher
def decrypt(ciphertext, key, char_set_size):
    """
    This function decrypts with vigenere. Instead of exponents, take the nth root.

    :param ciphertext: (string) the ciphertext to decrypt
    :param key: (string) the string to decrypt with
    :param char_set_size: (int) the size of the character set used
    :return: (string) the deciphered text
    """

    plaintext = ""
    key_index = 0
    char_counter = 0
    num_chars = ciphertext.count(" ")

    # Adjust the char set size to exclude surrogates (if necessary)
    if char_set_size > 256:
        char_set_size -= miscellaneous.SURROGATE_BOUND_LENGTH




    # While not finished processing ciphertext
    while ciphertext != "":


        # Print updates (every 1000 characters)
        if char_counter % 100 == 0:
            print("DECRYPTION\tPercent of text done: " + str((char_counter / num_chars) * 100))
        char_counter += 1


        # Read in one block/unit (one char, followed by a number, followed by a space). Then, update ciphertext
        char = ciphertext[0]
        number = int(float(ciphertext[1:ciphertext.find(" ")]))
        ciphertext = ciphertext[ciphertext.find(" ") + 1: ]

        #  figure out the unicode value for each of the characters(reverse surrogate adjustment in encryption if needed)
        uni_val_cipher = ord(char)
        if uni_val_cipher >= miscellaneous.SURROGATE_LOWER_BOUND:
            uni_val_cipher = uni_val_cipher - miscellaneous.SURROGATE_BOUND_LENGTH


        #  figure out the unicode value for the right character in the key, then update for next iteration
        uni_val_key = ord(key[key_index])
        key_index = (key_index + 1) % len(key)


        # Find the original plain char by taking all possibilities and raising that to uni_val_key'th power for match
        count = 1
        plain_char = "\0"
        for i in range(0, 256):
            # If overlap(count has not yet reached number)
            if pow(i, uni_val_key, char_set_size) == uni_val_cipher and count != number:
                count += 1
                continue
            # ELIF no more overlaps(overlap matches number)
            elif pow(i, uni_val_key, char_set_size) == uni_val_cipher and count == number:
                plain_char = chr(i)
                break


        # Add plain char to plaintext
        plaintext += plain_char


    return plaintext








