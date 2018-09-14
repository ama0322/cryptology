# noinspection PyUnresolvedReferences
from Cryptography_Cython.misc_cy cimport *








# Called from vigenere's encrypt_plaintext()
cpdef str encrypt_plaintext(str plaintext, str key, int alphabet_size):#region...
    """
    Encrypt the plaintext
    
    :param plaintext: (str) The plaintext to encrypt
    :param key:       (str) The key to encrypt with
    :param alphabet_size: (int) The size of the alphabet of available encrypted characters
    :return:              (str) The encrypted plaintext (the ciphertext)
    """



    # Important variables
    cdef list ciphertext    = [""] * len(plaintext) # Build up the plaintext here
    cdef int key_index      = 0                     # The index used to cycle through characters of the key
    cdef int key_len        = len(key)              # Length of key
    cdef int i              = 0                     # To iterate through a loop
    cdef list int_key = [ord_adjusted(character)    # List of unicode values of the key characters
                         for character in key]


    # Loop through each character, and encrypt them
    for i in range(0, len(plaintext)):

        # Figure out the encrypted character val and set in ciphertext
        ciphertext[i] = chr_adjusted( (ord_adjusted(plaintext[i]) + int_key[key_index])
                                             % alphabet_size )

        # Update the key index for the next character
        key_index = (key_index + 1) % key_len            # Update the key index




    # Join the ciphertext and return
    return "".join(ciphertext)
#endregion







# Called from vigenere's decrypt_ciphertext()
cpdef str decrypt_ciphertext(str ciphertext, str key, int alphabet_size):#region...
    """
    Loop algorithm to decrypt the ciphertext
    
    :param ciphertext:    (str) The ciphertext to decrypt
    :param key:           (key) To decrypt with 
    :param alphabet_size: (int) The size of the alphabet of this ciphertext
    :return:              (str) The decrypted plaintext
    """


    # Important variables
    cdef list plaintext                          # Build up the plaintext here
    cdef int key_index = 0                       # This is the index used for extracting the key_char
    cdef int key_len = len(key)                  # Length of key
    cdef int i = 0                               # To iterate through a list
    cdef list int_key = [ord_adjusted(character) # List of unicode values of the key characters
                         for character in key]



    # Use char for ascii/extended_ascii (these are faster)
    if alphabet_size <= 256:

        # Important variables setup
        plaintext = [""] * len(ciphertext) # Setup for the plaintext

        # Loop through every character, and decrypt them
        for i in range(0, len(ciphertext)):

            # Figure out the decrypted character val, and place in plaintext
            plaintext[i] = chr( (ord(ciphertext[i]) - int_key[key_index]) % alphabet_size )

            # Update the key index for the next character
            key_index = (key_index + 1) % key_len            # Update the key index





        # Join the plaintext together into a string, and return
        return "".join(plaintext)




    # Else, have to do it the hard way
    else:

        # Setup the array for plaintext
        plaintext = [""] * len(ciphertext)

        # Loop through every character, and decrypt them
        for i in range(0, len(ciphertext)):


            # Figure out the decrypted character val, and place in plaintext
            plaintext[i] = chr_adjusted( (ord_adjusted(ciphertext[i]) - int_key[key_index])
                                                % alphabet_size )

            # Update the key index for the next character
            key_index = (key_index + 1) % key_len            # Update the key index




        # Join the plaintext together into a string, and return
        return "".join(plaintext)
#endregion
























