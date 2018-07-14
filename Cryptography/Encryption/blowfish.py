from Cryptography import misc
import secrets # To generate a random key











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



    # Build up the ciphertext here
    ciphertext = ""


    # Blowfish encrypts text in 64-bit int blocks. Divide plaintext into hex, then int and save blocks.
    plaintext = plaintext.encode("utf-8").hex()[2 : ]       # Remove leading "0x"
    plaintext_blocks = []
    while plaintext != "":                                  # While there is still plaintext to process
        block = plaintext[0: 16]                            # 64 bits is equal to 16 hex digits
        plaintext_blocks.append(int(block, 16))             # Save integer value into plaintext_blocks list
        plaintext = plaintext[16:]                          # Update for next iteration
        print("Converting utf-8 to integer blocks: "        # Print updates
                + str(len(plaintext_blocks)) )


    # Encrypt the text
    key, p_array, s_boxes = _run_key_schedule()                            # Run the key schedule in preparation
    ciphertext_blocks = []                                                 # Build up ciphertext blocks here
    for i in range(len(plaintext_blocks)):
        ciphertext_blocks.append(_blowfish_on_64_bits(plaintext_blocks[i], # Run blowfish on each plaintext block
                                                      p_array, s_boxes))
        print("Encrypting: " + str((i / len(plaintext_blocks)) * 100)      # Print updates
                + "%")




    # Turn the blocks of integers into characters using the selected character encoding scheme
    ciphertext_blocks = [ hex(block)[2:] for block in ciphertext_blocks ]        # Turn int to hex, remove leading 0x
    for block in ciphertext_blocks:                                              # Concatenate all the hex strings
        ciphertext += block
    ciphertext = int(ciphertext, 16)                                             # Convert hex string to an int
    ciphertext = misc.int_to_chars_encoding_scheme(ciphertext,          # Encode int as characters
                                                            encoding_scheme)


    # Return the ciphertext and the generated key
    return ciphertext, misc.int_to_chars_encoding_scheme(key, encoding_scheme)









# Returns: key, p_array, s_boxes. Key schedule setup for the algorithm.
def _run_key_schedule():
    """

    :return: (string) the generated key (in encoded form)
    :return: (list) p_array to be used in encryption
    :return: (list) s_boxes to be used in encryption
    """

    # Generate a key (generates random bits)
    import Decryption.blowfish                                               # Cipher info located in Decryption folder
    return_key = secrets.randbits(Decryption.blowfish.key_bits)              # Generate num with right bitsize
    key = return_key.to_bytes((Decryption.blowfish.key_bits + 7)// 8, "big") # Turn to bytearray

    # First, copy over the base p_array and s_boxes from Decryption/blowfish.py
    p_array = Decryption.blowfish.p_array
    s_boxes = Decryption.blowfish.s_boxes

    # Each entry in p_array is XOR'ed with key, in groups of 4 bytes (32 bits), and cycling the key.
    for p_index in range(0, len(p_array)):
        val_to_xor =   (key[(p_index + 0) % len(key)] << 24)  \
                     + (key[(p_index + 1) % len(key)] << 16)  \
                     + (key[(p_index + 2) % len(key)] <<  8)  \
                     + (key[(p_index + 3) % len(key)] <<  0)
        p_array[p_index] = p_array[p_index] ^ val_to_xor


    # Run the blowfish cipher on a 64-bit zero block. The ciphertext halves will replace p_array[0] and p[1]. Those
    # two ciphertext halves are then encrypted together as a single block using the new p_array and s_boxes,
    # resulting in a new ciphertext that will replace p_array[2] and p_array[3]. This same process continues until
    # all of p_array and all of s_boxes have been replaced
    ciphertext = 0                                                       # Encryption process starts with all 0 block
    for two_entries in range(0, len(p_array), 2):                        # Start replacing p_array
        ciphertext = _blowfish_on_64_bits(ciphertext, p_array, s_boxes)  # Encryption processes uses last ciphertext
        p_array[two_entries]     = ciphertext & 0xFFFFFFFF00000000 >> 32 # Left half of ciphertext replaces curr entry
        p_array[two_entries + 1] = ciphertext & 0x00000000FFFFFFFF >> 0  # Right half replaces the entry right after

    for i in range(len(s_boxes)):                                        # Start replacing the s_boxes. Iterate 4 groups
        for j in range(0, len(s_boxes[i]), 2):                           # For each group in s_boxes, replace in twos
            ciphertext = _blowfish_on_64_bits(ciphertext, p_array, s_boxes)
            p_array[two_entries] = ciphertext & 0xFFFFFFFF00000000 >> 32
            p_array[two_entries + 1] = ciphertext & 0x00000000FFFFFFFF >> 0




    return return_key, p_array, s_boxes



# Returns: encrypted_block. The actual algorithm run on a 64-bit integer input.
def _blowfish_on_64_bits(input, p_array, s_boxes):
    """
    This is algorithm that runs on the 64-bit integer blocks

    :param input: (int) the 64-bit block of plaintext to encrypt
    :return: (int) the encrypted result
    """

    # F-function to be used during encryption
    def f_function(input):
        """
        This inner function performs the f_function in the 32-bit input

        :param input:(int) 32-bit input
        :return: (int) 32-bit output as a result of this function
        """


        # Obtain the bit patterns for each quarter (8-bits each) of the 32-bit number.
        far_left     = (input & 0xFF000000) >> 24
        center_left  = (input & 0x00FF0000) >> 16  # bit-mask out the unnecessary bits
        center_right = (input & 0x0000FF00) >> 8  # and shift all the way to one's place
        far_right    = (input & 0x000000FF) >> 0

        # Perform the +, ^, + operations on the mappings from s_boxes
        output =          s_boxes[0][far_left]
        output = output + s_boxes[1][center_left] % (2 ** 32)  # Obtain the modular result with 2^32
        output = output ^ s_boxes[2][center_right]
        output = output + s_boxes[3][far_right]   % (2 ** 32)  # Obtain the modular result with 2^32

        return output


    # Obtain the bit patterns of the left half and the right half
    left  = (input & 0xFFFF0000) >> 16
    right = (input & 0x0000FFFF) >>  0

    # Run the rounds 16 times
    for round in range(16):
        # Round operations:
        xor_result = left ^ p_array[round]      # get xor result of the left half with the r'th p_array entry
        f_result   = f_function(xor_result)     # apply the f_function to the xor_result
        right      = right ^ f_result           # update right with xor result of the right with the f_result

        # Swap the left and right values for the next iteration
        temp  =  left
        left  = right
        right =  left

    # Undo the last swap
    temp  =  left
    left  = right
    right =  left

    # Whiten the output
    left  = left  ^ p_array[17]                      # Last index
    right = right & p_array[16]                      # Second to last index

    # Combine the left and right and return
    return (left << 16) + right











