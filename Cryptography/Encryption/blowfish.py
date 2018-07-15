from Cryptography import misc


import secrets # To generate a random key
import copy    # To deepcopy
import time    # To time functions









# Encrypt using user-entered info. Write relevant information and return encrypted text for cryptography_runner
def execute(data, output_location):
    """
    This function calls the appropriate functions in misc.py. Those functions will use the encrypt() function
    located below as the algorithm to actually encrypt the text. Then, the ciphertext will be returned back to
    cryptography_runner.py

    :param data: (string) the data to be encrypted
    :param output_location: (string) the location to print out the information
    :return: (string) the encrypted data
    """

    # Decrypt the ciphertext. Write the plaintext and info to a file
    misc.execute_encryption_or_decryption(data, output_location,
                                                   "Encryption", "blowfish", "encrypt")





# Returns: ciphertext, generated_key. This function contains the algorithm to encrypt using blowfish cipher
def encrypt(plaintext, key, encoding_scheme):
    """
    This function contains the actual algorithm to encrypt with a blowfish cipher. The key is randomly generated,
    and is used during the key schedule when it is xor'ed with the p_array in a certain fashion. Because blowfish is
    a block cipher, if plaintext is larger than the 64-bit blocks that are used, it is divided up into smaller
    blocks. Blowfish is turned into blocks by turning the plaintext into a hex string through utf-8 intepretation.
    The hex string are then divided into blocks of 16 digits(64-bits each). Those hex string are then read as
    integers during the encryption process because of xor operations.


    :param plaintext:       (string) the text to be encrypted
    :param key:             NOT USED
    :param encoding_scheme: (string) The type of encoding scheme to use
    :return:                (string) the encrypted text
    """


    plaintext         = plaintext          # The plaintext to encrypt
    plaintext_blocks  = []                 # Build up the plaintext blocks here
    ciphertext_blocks = []                 # Build up the ciphertext blocks here
    ciphertext        = ""                 # Build up the ciphertext here



    # Blowfish encrypts text in 64-bit int blocks. Turn the plaintext into a hex string. Then, divide the string into 16
    # digits each (64-bits each). Then, turn those hex blocks into int blocks.
    plaintext = plaintext.encode("utf-8").hex()            # Convert to hex. Remove leading "0x"


    while plaintext != "":                                  # While there is still plaintext to process
        block = plaintext[-16:]                             # 64 bits is equal to 16 hex digits (read from end)
        plaintext_blocks.insert(0, (int(block, 16)))        # Save int value into plaintext_blocks
        plaintext = plaintext[:-16]                         # Cut out the portion that was just read




    # Conduct the key schedule (and time it)
    from Cryptography.Decryption import blowfish                               # import decryption type for vars
    p_array = copy.deepcopy(blowfish.p_array)
    s_boxes = copy.deepcopy(blowfish.s_boxes)
    start_time = time.time()
    key, p_array, s_boxes = run_key_schedule("", p_array, s_boxes)             # Run the key schedule
    blowfish.testing_execute.time_for_key_schedule = time.time() - start_time  # Save time in Decryption's blowfish


    # Encrypt the text (and save block information)
    for i in range(len(plaintext_blocks)):
        ciphertext_blocks.append(blowfish_on_64_bits(plaintext_blocks[i],   # Run blowfish on each plaintext block
                                                      p_array, s_boxes))
        #print("Encrypting: " + str((i / len(plaintext_blocks)) * 100)      # Print updates
        #        + "%")




    # Turn the blocks of ints into blocks of characters with encoding scheme. Then, concatenate for final ciphertext
    ciphertext_blocks = [ misc.int_to_chars_encoding_scheme_pad(block, encoding_scheme, 64)    # Each block is 64 bits
                                                            for block in ciphertext_blocks]
    for block in ciphertext_blocks:                                                            # Concatenate blocks
        ciphertext += block
    blowfish.testing_execute.num_blocks = len(ciphertext_blocks)            # Save block info into Decryption's blowfish
    blowfish.testing_execute.block_size = len(ciphertext_blocks[0])



    # Return the ciphertext and the generated key
    return ciphertext, misc.int_to_chars_encoding_scheme(key, encoding_scheme)









# Returns: key, p_array, s_boxes. Key schedule setup for the algorithm.
def run_key_schedule(key, p_array, s_boxes):
    """
    Key setup for blowfish

    :param: key     (string) the key to use (during decryption mode)
    :param: p_array (list) the p array
    :param: s_boxes (2-d list) the s boxes
    :return:        (string) the generated key (in encoded form)
    :return:        (list) p_array to be used in encryption
    :return:        (list) s_boxes to be used in encryption
    """



    if key == "":                                                        # If key not given, generate a key
        from Cryptography.Decryption import blowfish
        return_key = secrets.randbits(blowfish.key_bits)                 # Generate num with right bitsize (rand bits)
        key = return_key.to_bytes((blowfish.key_bits + 7) // 8, "big")   # Turn to bytearray (round up to nearest byte)

    else:                                                                # Else key is given. Use that
        from Cryptography.Decryption import blowfish
        return_key = key
        key = key.to_bytes((blowfish.key_bits + 7) // 8, "big")          # Turn to bytearray (round up to nearest byte)



    # Each entry in p_array is XOR'ed with key, in groups of 4 bytes (32 bits), and cycling the key.
    key_index = 0                                                            # Start with first four bytes of key
    for p_index in range(0, len(p_array)):
        val_to_xor        =   (key[ key_index      % len(key)] << 24)  \
                            + (key[(key_index + 1) % len(key)] << 16)  \
                            + (key[(key_index + 2) % len(key)] <<  8)  \
                            + (key[(key_index + 3) % len(key)]      )

        p_array[p_index] ^= val_to_xor                                        # XOR bytes with p_array element
        key_index += 4                                                        # Move key index up 4 bytes



    # Run the blowfish cipher on a 64-bit zero block. The ciphertext halves will replace p_array[0] and p[1]. Those
    # two ciphertext halves are then encrypted together as a single block using the new p_array and s_boxes,
    # resulting in a new ciphertext that will replace p_array[2] and p_array[3]. This same process continues until
    # all of p_array and all of s_boxes have been replaced
    ciphertext = 0                                                         # Encryption process starts with all 0 block
    for i in range(0, len(p_array), 2):                                    # Start replacing p_array
        ciphertext = blowfish_on_64_bits(ciphertext, p_array, s_boxes)     # Encryption processes uses last ciphertext
        p_array[i    ] = ciphertext & 0xFFFFFFFF00000000 >> 32             # Left half of ciphertext replaces curr entry
        p_array[i + 1] = ciphertext & 0x00000000FFFFFFFF                   # Right half replaces the entry right after


    for i in range(len(s_boxes)):                                          # s_boxes: Iterate through outer 4 objects
        for j in range(0, len(s_boxes[i]), 2):                             # For each group in s_boxes, replace in twos
            ciphertext = blowfish_on_64_bits(ciphertext, p_array, s_boxes)
            s_boxes[i][j    ] = ciphertext & 0xFFFFFFFF00000000 >> 32
            s_boxes[i][j + 1] = ciphertext & 0x00000000FFFFFFFF



    return return_key, p_array, s_boxes





# Returns: encrypted_block. The actual algorithm run on a 64-bit integer input.
def blowfish_on_64_bits(input, p_array, s_boxes):
    """
    This is algorithm that runs on the 64-bit integer blocks

    :param input:   (int) the 64-bit block of plaintext to encrypt
    :param p_array: (list) the p array
    :param s_boxes: (2-d list) the s boxes
    :return:        (int) the encrypted result
    """

    # F-function to be used during encryption
    def f_function(input):
        """
        This inner function performs the f_function in the 32-bit input

        :param input:(int) 32-bit input
        :return:     (int) 32-bit output as a result of this function
        """


        # Obtain the bit patterns for each quarter (8-bits each) of the 32-bit number.
        far_left     = (input & 0xFF000000) >> 24
        center_left  = (input & 0x00FF0000) >> 16  # bit-mask out the unneeded bits and shift all the way to one's place
        center_right = (input & 0x0000FF00) >> 8
        far_right    = (input & 0x000000FF)

        # Perform the +, ^, + operations on the mappings from s_boxes (s_boxes elements are 32 bits)
        output =          s_boxes[0][far_left    ]
        output = (output + s_boxes[1][center_left ]) % 4294967296  # Obtain the modular result with 2^32
        output = (output ^ s_boxes[2][center_right])
        output = (output + s_boxes[3][far_right   ]) % 4294967296  # Obtain the modular result with 2^32


        return output



    # Obtain the bit patterns of the left half and the right half
    left  = (input & 0xFFFFFFFF00000000) >> 32                           # Left 32 bits
    right = (input & 0x00000000FFFFFFFF)                                 # Right 32 bits



    # Run the rounds 16 times (for indices 0, 1, ...15)
    for i in range(16):

        # Round operations:
        left     ^= p_array[i]              # update left with xor result of left with the p_array element (32 bits)
        f_result  = f_function(left)        # apply the f_function to the xor_result
        right    ^= f_result                # update right with xor result of the right with the f_result


        # Swap the left and right values for the next iteration
        left, right = right, left

    # Undo the last swap (just re-swap)
    left, right = right, left

    # Whiten the output
    right = right ^ p_array[16]                      # Second to last index
    left  = left  ^ p_array[17]                      # Last index




    # Combine the left and right and return the 64 bits
    return (left << 32) + right











