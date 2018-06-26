import miscellaneous
import time








def execute(data, output_location):
    """
    This function decrypts data using a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the location to save relevant info into
    :return: (string) the decrypted data
    """


    # Obtain the decrypted text. Also write statistics and relevant info to a file
    decrypted = miscellaneous.encrypt_or_decrypt_without_key(data, output_location,
                                                                      "Decryption", "vigenere_nokey", "decrypt")


    # Return encrypted text to be written in cryptography_runner
    return decrypted



# Decrypt in testing mode. So add more statistics about performance. Check for correctness
def testing_execute(cipher_text, output_location, plain_text, encryption_time):
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
    decrypted, char_set, key, percent_english = decrypt(cipher_text)
    decryption_time = time.time() - start_time

    # Open file for writing
    new_file = open(output_location, "w", encoding="utf-8")

    # Set up a space for notes
    if decrypted == plain_text:
        new_file.writelines(["Vigenere without key\nCORRECT \n\n\nNotes: "])
    else:
        # Calculate the number of characters that differ
        count = sum(1 for a, b in zip(decrypted, plain_text) if a != b)
        new_file.writelines(["Vigenere without key" + "\nINCORRECT"
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
                         "\nThe character set is : " + char_set,
                         "\nThe key is: " + key,
                         "\nThe percent of words that are English are : " + str(percent_english),
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






# Contains the actual algorithm to decrypt with vigenere cipher without a key TODO
def decrypt(cipher_text):
    """
    This function decrypts a vigenere cipher without a key

    :param cipher_text: (string) the cipher text to decrypt
    :return: (string) the deciphered text
    """

    plain_text = "" # Build up the decrypted text here
    key_index = 0 # The index of the current char in the key. Iterates from 0 to len() - 1 and repeats.


    for x in cipher_text:

        #  figure out the unicode value for each of the characters
        uni_val_cipher = ord(x)

        #  figure out the unicode value for the right character in the key, then update for next iteration
        key_char = key[key_index]
        uni_val_key = ord(key_char)
        key_index = (key_index + 1) % len(key)


        #  figure out the character by subtracting the two unicodes, the add it to the decrypted string
        decrypted_char = chr((uni_val_cipher - uni_val_key) % char_set_size)
        plain_text = plain_text + decrypted_char


    return plain_text








