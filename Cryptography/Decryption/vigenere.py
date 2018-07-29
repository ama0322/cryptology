from Cryptography import misc


# Cipher info:
char_set = misc.ALPHABETS
cipher_type = "symmetric"
key_size = "multiple characters"
ciphertext_alphabet_restricted = True






########################################################################################## STANDARD FUNCTIONS ##########


# Call the proper functions to decrypt. Return decrypted text back to cryptography_runner.py
def execute(data, output_location):
    """
    This function decrypts data using a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the location to save relevant info into
    :return: (string) the decrypted data
    """


    # Encrypt the plaintext. Print out the ciphertext and relevant information
    misc.execute_encryption_or_decryption(data, output_location, "Decryption", "vigenere", "decrypt")




# Figure out the encryption and decryption code. Pass info to misc' testing_execute function
def testing_execute(encryption, decryption, plaintext, plaintext_source, encryption_key, alphabet_size,
                    output_location):
    """
    Conducts a vigenere decryption in testing mode

    :param encryption: (string) the name of the encryption cipher to use
    :param decryption: (string) the name of the decryption cipher to use (this)
    :param plaintext_source: (string) the location where the plaintext is found
    :param plaintext: (string) the plaintext to encrypt
    :param encryption_key: (string) the key to use to encrypt
    :param alphabet_size: (int) the size of the character set to use
    :param output_location: (string) the name of the file to write statistics in
    :return: None
    """


    # Encryption code
    encryption_code = misc.GENERAL_ENCRYPTION_CODE

    # Decryption code
    decryption_code = misc.GENERAL_DECRYPTION_CODE

    misc.testing_execute_encryption_and_decryption(encryption, decryption,
                                                            plaintext, plaintext_source, encryption_key, alphabet_size,
                                                            output_location,
                                                            "Vigenère",
                                                            encryption_code, decryption_code)







# Returns string. This is the actual algorithm to decrypt
def decrypt(ciphertext, key, alphabet_size):
    """
    This function decrypts with vigenere. Instead of adding, subtract

    :param ciphertext: (string) the ciphertext to decrypt
    :param key: (string) the key to decrypt with
    :param alphabet_size: (integer) the size of the character set that is used
    :return: (string) the deciphered text
    """

    # Build up the decrypted text here
    plaintext = ""

    # The index of the current char in the key. Iterates from 0 to len() - 1 and repeats.
    key_index = 0


    for x in ciphertext:

        #  figure out the unicode value for each of the characters
        uni_val_cipher = ord(x)

        #  figure out the unicode value for the right character in the key, then update for next iteration
        uni_val_key = ord(key[key_index])
        key_index = (key_index + 1) % len(key)


        #  figure out the character by subtracting the two unicodes, the add it to the decrypted string
        decrypted_char = chr(   (uni_val_cipher - uni_val_key) % alphabet_size   )
        plaintext += decrypted_char


    return plaintext





