from Cryptography import misc



# Cipher info:
char_set = misc.ALPHABETS
cipher_type = "symmetric"
key_size = "single character"
ciphertext_alphabet_restricted = True




########################################################################################## STANDARD FUNCTIONS ##########


# Decrypt using user-entered info. Write relevant information and return decrypted text for cryptography_runner
def execute(data:str, output_location:str) -> None:
    """
    This function decrypts data using a user-provided key.

    :param data:            (str) the data to be decrypted
    :param output_location: (str) the location to write out relevant info and statistics
    :return:                None
    """


    # Decrypt the ciphertext. Write the plaintext and info to a file
    misc.execute_encryption_or_decryption(data, output_location, "Decryption", "rotation", "decrypt")





# Figure out the encryption and decryption code. Pass info to misc' testing_execute function
def testing_execute(encryption:str, decryption:str, plaintext:str, plaintext_source:str, encryption_key:str,
                    alphabet_size:int, output_location:str) -> None:
    """
    Conducts a rotation decryption in testing mode

    :param encryption:       (str) the name of the encryption cipher to use
    :param decryption:       (str) the name of the decryption cipher to use (this)
    :param plaintext_source: (str) the location where the plaintext is found
    :param plaintext:        (str) the plaintext to encrypt
    :param encryption_key:   (str) the key to use to encrypt
    :param alphabet_size:    (int) the size of the character set to use
    :param output_location:  (str) the name of the file to write statistics in
    :return: None
    """


    # Encryption code
    encryption_code = misc.GENERAL_ENCRYPTION_CODE

    # Decryption code
    decryption_code = misc.GENERAL_DECRYPTION_CODE

    misc.testing_execute_encryption_and_decryption(encryption, decryption,
                                                            plaintext, plaintext_source, encryption_key, alphabet_size,
                                                            output_location,
                                                            "Rotation",
                                                            encryption_code, decryption_code)






# Returns string. This is the actual algorithm to decrypt
def decrypt(ciphertext:str, key:str, alphabet_size:int) -> str:
    """
    This function decrypts the ciphertext using the set of unicode characters from 0 to end_char.

    :param ciphertext:    (str) the text to be encrypted
    :param key:           (str) the key with which the encryption is done
    :param alphabet_size: (int) The number of characters in the character set
    :return:              (str) the encrypted text
    """

    encrypted = [] # the list to build up the encrypted text
    key_index = 0 # the index in the key we are using for the vigenere encrypt


    for x in ciphertext:
        #  figure out the unicode value for the current character
        uni_val_cipher = ord(x)

        #  figure out the unicode value for the right character in the key. THen, update key_index for next iteratio
        uni_val_key = ord(key[key_index])
        key_index = (key_index + 1) % len(key)


        #  figure out the character by subtracting the two ascii's, the add it to the encrypted string
        encrypted_char = chr((uni_val_cipher - uni_val_key) % alphabet_size)
        encrypted.append(encrypted_char)



    encrypted = "".join(encrypted)


    return encrypted









