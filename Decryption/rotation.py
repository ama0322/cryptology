import miscellaneous
import time # for timing






# Decrypt using user-entered info. Write relevant information and return decrypted text for cryptography_runner
def execute(data, output_location):
    """
    This function decrypts data using a user-provided key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the location to write out relevant info and statistics
    :return: (string) the decrypted data
    """

    # Obtain the decrypted text. Also write statistics and relevant info to a file
    decrypted = miscellaneous.encrypt_or_decrypt_with_single_char_key(data, output_location,
                                                                      "Decryption", "rotation", "decrypt")


    # Return encrypted text to be written in cryptography_runner
    return decrypted




# Decrypt in testing mode. So add more statistics about performance. Check for correctness
def testing_execute(cipher_text, output_location, plain_text, key, char_set_size, encryption_time):
    """
    Conducts a rotation decryption in testing mode

    :param cipher_text: (string) the cipher text to decrypt
    :param output_location: (string) the file to store statistics about decryption
    :param plain_text: (string) the plain text to check for correctness
    :param key: (string) the key to decrypt with
    :param char_set_size: (integer) the size of the character set used
    :param encryption_time: (double) the time that encryption took
    :return: None
    """

    # Run the decryption algorith on the cipher_text
    start_time = time.time()
    decrypted = decrypt(cipher_text, key, char_set_size)
    decryption_time = time.time() - start_time

    # Open file for writing
    new_file = open(output_location, "w", encoding="utf-8")

    # Set up a space for notes
    if decrypted == plain_text:
        new_file.writelines(["CORRECT \nNotes: "])
    else:
        new_file.writelines(["INCORRECT \nNotes: "])

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
                                                        value in miscellaneous.char_set_to_char_set_size.items()
                                                        if value == char_set_size][0],
                         "\nThe key is: " + key,
                         "\nDecrypted in: " + str(decryption_time) + " seconds.",
                         "\nThat is " + str(encryption_time / len(decrypted)) + " seconds per character.",
                         "\nThat is " + str((decryption_time / len(decrypted) * 1000000))
                                      + " microseconds per character."                                         ])

    new_file.close()






# This function contains the actual algorithm to decrypt a rotation cipher with a key
def decrypt(cipher_text, key, char_set_size):
    """
    This function decrypts the cipher_text using the set of unicode characters from 0 to end_char.

    :param plain_text: (string )the text to be encrypted
    :param key: (string) the key with which the encryption is done
    :param char_set_size: (int) The number of characters in the character set
    :return: (string) the encrypted text
    """

    encrypted = "" # the string to build up the encrypted text
    key_index = 0 # the index in the key we are using for the vigenere encrypt


    for x in cipher_text:
        #  figure out the unicode value for the current character
        uni_val_cipher = ord(x)

        #  figure out the unicode value for the right character in the key
        key_char = key[key_index]
        uni_val_key = ord(key_char)


        #  figure out the character by subtracting the two ascii's, the add it to the encrypted string
        encrypted_char = chr((uni_val_cipher - uni_val_key) % (char_set_size))
        encrypted = encrypted + encrypted_char

        # update key_index for next iteration
        key_index = (key_index + 1) % len(key)

    return encrypted


