from Cryptography import misc

# Cipher info:
alphabet = misc.char_sets
cipher_type = "symmetric"
key_size = "multiple characters"




# Call the proper functions to decrypt. Return decrypted text back to cryptography_runner.py
def execute(data, output_location):
    """
    This function decrypts data using a key.

    :param data: (string) the data to be decrypted
    :param output_location: (string) the file to write relevant information into
    :return: (string) the decrypted data
    """


    # Encrypt the plaintext. Print out the ciphertext and relevant information
    misc.execute_encryption_or_decryption(data, output_location,
                                                   "Decryption", "vigenere_multiplicative", "decrypt")




# Figure out the encryption and decryption code. Pass info to misc' testing_execute function
def testing_execute(encryption, decryption, plaintext, encryption_key, char_set_size, output_location):
    """
    Conducts a rotation decryption in testing mode

    :param encryption: (string) the name of the encryption cipher to use
    :param decryption: (string) the name of the decryption cipher to use (this)
    :param plaintext: (string) the plaintext to encrypt
    :param encryption_key: (string) the key to use to encrypt
    :param char_set_size: (int) the size of the character set to use
    :param output_location: (string) the name of the file to write statistics in
    :return: None
    """


    # Encryption code
    encryption_code = misc.general_encryption_code

    # Decryption code
    decryption_code = misc.general_decryption_code

    misc.testing_execute_encryption_and_decryption(encryption, decryption,
                                                            plaintext, encryption_key, char_set_size,
                                                            output_location,
                                                            "Vigenère using Modular Multiplication",
                                                            encryption_code, decryption_code)





# Returns string. This is the actual algorithm to decrypt
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
        char_set_size -= misc.SURROGATE_BOUND_LENGTH




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
        if uni_val_cipher >= misc.SURROGATE_LOWER_BOUND:
            uni_val_cipher = uni_val_cipher - misc.SURROGATE_BOUND_LENGTH


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











