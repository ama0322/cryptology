from Cryptography_Cython import misc_c









# Main algorithm for vigenere's encrypt_plaintext()
cpdef str encrypt_plaintext_loop(str plaintext, str key, int alphabet_size):#region...
    """
    Encrypt the plaintext
    
    :param plaintext: (str) The plaintext to encrypt
    :param key:       (str) The key to encrypt with
    :param alphabet_size: (int) The size of the alphabet of available encrypted characters
    :return:              (str) The encrypted plaintext (the ciphertext)
    """



    # Important variables
    cdef list ciphertext = [""] * len(plaintext) # Build up the plaintext here
    cdef int key_index   = 0                     # The index used to cycle through characters of the key


    # Loop through each character, and encrypt them
    for i in range(0, len(plaintext)):

        # Figure out the encrypted character val
        encrypted_char = misc_c.chr_adjusted( (misc_c.ord_adjusted(plaintext[i])
                                               + misc_c.ord_adjusted(key[key_index]))
                                              % alphabet_size )

        # Update the key index for the next character
        key_index = (key_index + 1) % len(key)            # Update the key index

        # Place the encrypted_char into the ciphertext list
        ciphertext[i] = encrypted_char

        # Print updates
        misc_c.print_updates("DECRYPTION", i + 1, len(plaintext))


    # Join the ciphertext and return
    return "".join(ciphertext)
#endregion







# Main algorithm for vigenere's decrypt_ciphertext()
cpdef str decrypt_ciphertext_loop(str ciphertext, str key, int alphabet_size):#region...
    """
    Loop algorithm to decrypt the ciphertext
    
    :param ciphertext: (str) The ciphertext to decrypt
    :param key:        (key) To decrypt with 
    :param alphabet_size:  (int) The size of the alphabet of this ciphertext
    :return:               (str) The decrypted plaintext
    """


    # Important variables
    plaintext = [""] * len(ciphertext) # Build up the plaintext here
    key_index = 0                      # This is the index used for extracting the key_char


    # Loop through every character, and decrypt them
    for i in range(0, len(ciphertext)):


        # Figure out the decrypted character val
        decrypted_char = misc_c.chr_adjusted( (misc_c.ord_adjusted(ciphertext[i])
                                               - misc_c.ord_adjusted(key[key_index]))
                                              % alphabet_size )

        # Update the key index for the next character
        key_index = (key_index + 1) % len(key)            # Update the key index

        # Place the decrypted_char into the plaintext list
        plaintext[i] = decrypted_char

        # Print updates
        misc_c.print_updates("DECRYPTION", i + 1, len(ciphertext))


    # Join the plaintext together into a string, and return
    return "".join(plaintext)
#endregion





























