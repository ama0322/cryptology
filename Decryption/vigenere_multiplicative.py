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

    # Encryption code
    encryption_code = miscellaneous.general_encryption_code

    # Decryption code
    decryption_code = miscellaneous.general_decryption_code

    miscellaneous.testing_general_decrypt_with_key(ciphertext, output_location, plaintext, key, key, char_set_size,
                                                   encryption_time, "Decryption", "vigenere_multiplicative",
                                                   "Vigenère Multiplicative", "decrypt", encryption_code,
                                                   decryption_code)




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
        number = int(ciphertext[1:ciphertext.find(" ")], 10)
        ciphertext = ciphertext[ciphertext.find(" ") + 1: ]

        #  figure out the unicode value for each of the characters(reverse surrogate adjustment in encryption if needed)
        uni_val_cipher = ord(char)
        if uni_val_cipher >= miscellaneous.SURROGATE_LOWER_BOUND:
            uni_val_cipher = uni_val_cipher - miscellaneous.SURROGATE_BOUND_LENGTH


        #  figure out the unicode value for the right character in the key, then update for next iteration
        uni_val_key = ord(key[key_index])
        key_index = (key_index + 1) % len(key)


        # Find the original plain char by taking all possibilities and raising that to uni_val_key'th power for match
        count = 0
        plain_char = "\0"
        for i in range(0, 1114112):

            # If overlap(count has not yet reached number)
            if (i * uni_val_key) % char_set_size == uni_val_cipher and count != number:
                count += 1
                continue
            # ELIF no more overlaps(overlap matches number)
            elif (i * uni_val_key) % char_set_size == uni_val_cipher and count == number:
                plain_char = chr(i)
                break


        # Add plain char to plaintext
        plaintext += plain_char


    return plaintext











