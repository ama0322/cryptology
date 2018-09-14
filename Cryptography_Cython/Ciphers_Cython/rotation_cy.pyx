# noinspection PyUnresolvedReferences
from Cryptography_Cython.misc_cy cimport *












# Called from rotation's encrypt_plaintext()
cpdef str encrypt_plaintext(str plaintext, str key, int alphabet_size):#region...
    """
    Encrypt the plaintext.
    
    :param plaintext:     (str) The plaintext to encrypt
    :param key:           (str) The key to encrypt with
    :param alphabet_size: (int) The size of the alphabet of available encrypted characters
    :return:              (str) The encrypted plaintext (the ciphertext)
    """



    # Important variables
    cdef list ciphertext                        # Build up the plaintext here
    cdef int i              = 0                 # To iterate through a loop
    cdef int int_key        = ord_adjusted(key)




    # Use char for ascii/extended_ascii (these are faster)
    if alphabet_size <= 256:

        # Important variables setup
        ciphertext = [""] * len(plaintext) # Setup for the plaintext

        # Loop through every character, and encrypt them
        for i in range(0, len(plaintext)):

            # Figure out the decrypted character val, and place in plaintext
            ciphertext[i] = chr( (ord(plaintext[i]) + int_key) % alphabet_size )




        # Join the plaintext together into a string, and return
        return "".join(ciphertext)




    # Else, have to use chr_adjusted() and ord_adjusted()
    else:

        # Important variables setup
        ciphertext = [""] * len(plaintext) # Setup for the plaintext

        # Loop through each character, and encrypt them
        for i in range(0, len(plaintext)):

            # Figure out the encrypted character val and set in ciphertext
            ciphertext[i] = chr_adjusted( (ord_adjusted(plaintext[i]) + int_key) % alphabet_size )






        # Join the ciphertext and return
        return "".join(ciphertext)
#endregion







# Called from rotation's decrypt_ciphertext()
cpdef str decrypt_ciphertext(str ciphertext, str key, int alphabet_size):#region...
    """
    Loop algorithm to decrypt the ciphertext
    
    :param ciphertext:    (str) The ciphertext to decrypt
    :param key:           (key) To decrypt with 
    :param alphabet_size: (int) The size of the alphabet of this ciphertext
    :return:              (str) The decrypted plaintext
    """


    # Important variables
    cdef list plaintext                     # Build up the plaintext here
    cdef int i          = 0                 # To iterate through a list
    cdef int int_key    = ord_adjusted(key) # The unicode value of the key



    # Use char for ascii/extended_ascii (these are faster)
    if alphabet_size <= 256:

        # Important variables setup
        plaintext = [""] * len(ciphertext) # Setup for the plaintext

        # Loop through every character, and decrypt them
        for i in range(0, len(ciphertext)):

            # Figure out the decrypted character val, and place in plaintext
            plaintext[i] = chr( (ord(ciphertext[i]) - int_key) % alphabet_size )





        # Join the plaintext together into a string, and return
        return "".join(plaintext)




    # Else, have to do it the hard way
    else:

        # Setup the array for plaintext
        plaintext = [""] * len(ciphertext)

        # Loop through every character, and decrypt them
        for i in range(0, len(ciphertext)):


            # Figure out the decrypted character val, and place in plaintext
            plaintext[i] = chr_adjusted( (ord_adjusted(ciphertext[i]) - int_key) % alphabet_size )







        # Join the plaintext together into a string, and return
        return "".join(plaintext)
#endregion






































