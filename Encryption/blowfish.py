import miscellaneous
import secrets # To generate a random key











# Encrypt using user-entered info. Write relevant information and return encrypted text for cryptography_runner
def execute(data, output_location):
    """
    This function calls the appropriate functions in miscellaneous.py. Those functions will use the encrypt() function
    located below as the algorithm to actually encrypt the text. Then, the ciphertext will be returned back to
    cryptography_runner.py

    :param data: (string) the data to be encrypted
    :param output_location: (string) the location to print out the information
    :return: (string) the encrypted data
    """

    # Obtain the encrypted text. Also write statistics and relevant info a file
    encrypted = miscellaneous.symmetric_ed_without_key(data, output_location,
                                                                      "Encryption", "rotation", "encrypt")


    # Return encrypted text to be written in cryptography_runner
    return encrypted





# This function contains the algorithm to encrypt using blowfish cipher
def encrypt(plaintext, key, char_encoding_scheme_size):
    """
    This function contains the actual algorithm to encrypt with a blowfish cipher. The key is randomly generated,
    and is used during the key schedule when it is xor'ed with the p_array in a certain fashion. Because blowfish is
    a block cipher, if plaintext is larger than the 64-bit blocks that are used, it is divided up into smaller
    blocks. Blowfish is turned into blocks by turning the plaintext into a hex string through utf-8 intepretation.
    The hex string are then divided into blocks of 16 digits(64-bits each). Those hex string are then read as
    integers during the encryption process because of xor operations.


    :param plaintext: (string )the text to be encrypted
    :param key: NOT USED
    :param char_encoding_scheme_size: (int) The number of characters in the encoding scheme
    :return: (string) the encrypted text
    """

    # The actual algorithm run on a 64-bit integer input
    def blowfish_on_64_bits(input, key):
        """
        This is algorithm that runs on the 64-bit integer blocks

        :param input: (int) the 64-bit block of plaintext to encrypt
        :param key: (int) the key used to encrypt
        :return: (int) the encrypted result
        """

        # F-function to be used during encryption
        def f_function(input):
            """
            This inner function performs the f_function in the 32-bit input

            :param input:(int) 32-bit input
            :return: (int) 32-bit output as a result of this function
            """

            # Convert the 32-bit integer input into a binary string (Remove leading "0b")
            input = bin(input)[2:]

            # Obtain the bit patterns for each quarter (8-bits) of the 32-bit number.
            far_left     = (input & 0xFF000000) >> 24
            center_left  = (input & 0x00FF0000) >> 16            # bit-mask out the unnecessary bits
            center_right = (input & 0x0000FF00) >> 8             # and shift all the way to one's place
            far_right    = (input & 0x000000FF) >> 0

            # Perform the +, ^, + operations on the mappings from s_boxes
            output =          s_boxes[0][far_left]
            output = output + s_boxes[1][center_left]  % (0xFFFFFFFF + 1)
            output = output ^ s_boxes[2][center_right] % (0xFFFFFFFF + 1)    # Obtain the modular result with 2^32
            output = output + s_boxes[3][far_right]    % (0xFFFFFFFF + 1)

            return output


        # Obtain the bit patterns of the left half and the right half
        left  = (input & 0xFFFF0000) >> 16
        right = (input & 0x0000FFFF) >> 0

        # Run the rounds 16 times
        for round in range(16):

            # Round operations:
            xor_result = left ^ p_array[round]            # get xor result of the left half with the r'th p_array entry
            f_result   = f_function(xor_result)           # apply the f_function to the xor_result
            right      = right ^ f_result                 # update right with xor result of the right with the f_result

            # Swap the left and right values for the next iteration
            temp  = left
            left  = right
            right = left


        # Undo the last swap
        temp  = left
        left  = right
        right = left

        # Whiten the output
        left  = left  ^ p_array[18]
        right = right & p_array[17]


        # Combine the left and right and return
        return (left << 16) + right


    # Build up the ciphertext here
    ciphertext = ""


    # Generate a key (generates random bits)
    from Decryption import blowfish
    key = secrets.randbits(blowfish.key_bit_length)         # Generate integer with the number of bits specified
    key = bin(key)[ 2: ]                                    # Turn to bitstring

    # Generate the p-array and the s-boxes. First, copy over the p_array and s_boxes from Decryption/blowfish.py
    p_array = blowfish.p_array
    s_boxes = blowfish.s_boxes

    # Each entry in p_array is XOR'ed with key, in groups of 4 bytes, and cycling the key if necessary.
    for i in range(len(p_array)):
        byte_index = i * 32
        val_to_xor =   ( int(  key[(byte_index +  0) % len(key): (byte_index +  8) % len(key)], 2  ) << 24 )         \
                     + ( int(  key[(byte_index +  8) % len(key): (byte_index + 16) % len(key)], 2  ) << 16 )         \
                     + ( int(  key[(byte_index + 16) % len(key): (byte_index + 24) % len(key)], 2  ) <<  8 )         \
                     + ( int(  key[(byte_index + 24) % len(key): (byte_index + 32) % len(key)], 2  ) <<  0 )
        p_array[i] = p_array[i] ^ val_to_xor



    # Blowfish encrypts text in 64-bit int blocks. Divide plaintext into hex, then int and save blocks.
    plaintext = plaintext.encode("utf-8").hex()[2 : ]       # Remove leading "0x"
    plaintext_blocks = []
    while plaintext != "":                                  # While there is still plaintext to process
        block = plaintext[0: 16]                            # 64 bits is equal to 16 hex digits
        plaintext_blocks.append(int(block, 16))             # Save integer value into plaintext_blocks list
        plaintext = plaintext[16:]                          # Update for next iteration



    # Run the blowfish algorithm on each integer block
    ciphertext_blocks = [ blowfish_on_64_bits(block) for block in plaintext_blocks ]


    # Figure out which char encoding scheme to use(reverse dictionary lookup)
    char_encoding_scheme = [key for key, value in miscellaneous.char_set_to_char_set_size.items()
                                                                            if value == char_encoding_scheme_size][0]

    # Turn the blocks of integers into characters using the selected character encoding scheme
    ciphertext_blocks = [ hex(block)[2:] for block in ciphertext_blocks ]        # Turn int to hex, remove leading 0x
    for block in ciphertext_blocks:                                              # Concatenate all the hex strings
        ciphertext += block
    ciphertext = int(ciphertext, 16)                                             # Convert hex string to an int
    ciphertext = miscellaneous.int_to_chars_encoding_scheme(ciphertext,          # Encode int as characters
                                                            char_encoding_scheme)

    
    return ciphertext






