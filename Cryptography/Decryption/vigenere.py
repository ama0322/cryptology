from Cryptography import misc


# Cipher info:
char_set = misc.ALPHABETS
cipher_type = "symmetric"
key_size = "multiple characters"
ciphertext_alphabet_restricted = True






########################################################################################## STANDARD FUNCTIONS ##########


# Call the proper functions to decrypt. Return decrypted text back to cryptography_runner.py
def execute(data:str, output_location:str) -> None:
    """
    This function decrypts data using a key.

    :param data:            (str) the data to be decrypted
    :param output_location: (str) the location to save relevant info into
    :return:                None
    """


    # Encrypt the plaintext. Print out the ciphertext and relevant information
    misc.execute_encryption_or_decryption(data, output_location, "Decryption", "vigenere", "decrypt")




# Figure out the encryption and decryption code. Pass info to misc' testing_execute function
def testing_execute(encryption:str, decryption:str, plaintext:str, plaintext_source:str, encryption_key:str,
                    alphabet_size:int, output_location:str) -> None:
    """
    Conducts a vigenere decryption in testing mode

    :param encryption:       (str) the name of the encryption cipher to use
    :param decryption:       (str) the name of the decryption cipher to use (this)
    :param plaintext_source: (str) the location where the plaintext is found
    :param plaintext:        (str) the plaintext to encrypt
    :param encryption_key:   (str) the key to use to encrypt
    :param alphabet_size:    (int) the size of the character set to use
    :param output_location:  (str) the name of the file to write statistics in
    :return:                 None
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
def decrypt(ciphertext:str, key:str, alphabet_size:int) -> str:
    """
    This function decrypts with vigenere. Instead of adding, subtract

    :param ciphertext:    (str) the ciphertext to decrypt
    :param key:           (str) the key to decrypt with
    :param alphabet_size: (int) the size of the character set that is used
    :return:              (str) the deciphered text
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





