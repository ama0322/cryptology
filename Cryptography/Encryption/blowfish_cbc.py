from Cryptography.Decryption import blowfish          # To get access to blowfish cipher auxiliary functions
from Cryptography.Decryption import blowfish_cbc      # To get blowfish_cbc info and store time data there

from Cryptography import misc

import copy                                           # To deepcopy p_array and s_boxes from Decryption's blowfish
import time                                           # To time functions (for testing_execute())
import secrets                                        # To generate the random IV








########################################################################################## STANDARD FUNCTIONS ##########

# Encrypt using user-entered info. Write relevant information and return encrypted text for cryptography_runner
def execute(data:str, output_location:str) -> None:
    """
    This function calls the appropriate functions in misc.py. Those functions will use the encrypt() function
    located below as the algorithm to actually encrypt the text. Then, the ciphertext will be returned back to
    cryptography_runner.py

    :param data:            (str) the data to be encrypted
    :param output_location: (str) the location to print out the information
    :return:                None
    """

    # Decrypt the ciphertext. Write the plaintext and info to a file
    misc.execute_encryption_or_decryption(data, output_location,
                                                   "Encryption", "blowfish_cbc", "encrypt")





# Returns: ciphertext, generated_key. This function contains the algorithm to encrypt using blowfish cipher
def encrypt(plaintext:str, key:str, encoding_scheme:str) -> (str, str):
    """
    This function contains the actual algorithm to encrypt with a blowfish cipher. The key is randomly generated,
    and is used during the key schedule when it is xor'ed with the p_array in a certain fashion. Because blowfish is
    a block cipher, if plaintext is larger than the 64-bit blocks that are used, it is divided up into smaller
    blocks. Blowfish is turned into blocks by turning the plaintext into a hex string through utf-8 interpretation.
    The hex string are then divided into blocks of 16 digits(64-bits each). Those hex string are then read as
    integers during the encryption process because of xor operations.


    :param plaintext:       (str)    the text to be encrypted
    :param key:             NOT USED
    :param encoding_scheme: (str)    The type of encoding scheme to use
    :return:                (str)    the encrypted text
    """


    plaintext         = plaintext          # The plaintext to encrypt
    plaintext_blocks  = []                 # Build up the plaintext blocks here
    ciphertext_blocks = []                 # Build up the ciphertext blocks here
    ciphertext        = ""                 # Build up the ciphertext here



    # Blowfish encrypts text in 64-bit int blocks. Turn the plaintext into a hex string. Then, divide the string into 16
    # digits each (64-bits each). Then, turn those hex blocks into int blocks.
    plaintext = plaintext.encode("utf-8").hex()            # Convert to hex. Remove leading "0x"

    original_plaintext_len = len(plaintext)
    while plaintext != "":                                  # While there is still plaintext to process
        block = plaintext[-16:]                             # 64 bits is equal to 16 hex digits (read from end)
        plaintext_blocks.insert(0, (int(block, 16)))        # Save int value into plaintext_blocks
        plaintext = plaintext[:-16]                         # Cut out the portion that was just read
        print("To encryption blocks: "
                + str((len(plaintext_blocks) * 16
                       / original_plaintext_len) * 100)
                + "%")




    # Conduct the key schedule (and time it)
    p_array = copy.deepcopy(blowfish.p_array)
    s_boxes = copy.deepcopy(blowfish.s_boxes)
    start_time = time.time()
    key, p_array, s_boxes = blowfish.run_key_schedule(0, p_array, s_boxes)         # Run the key schedule
    blowfish.testing_execute.time_for_key_schedule = time.time() - start_time       # Save time in Decryption's blowfish


    # Encrypt the text (and save block information)
    for i in range(len(plaintext_blocks)):
        ciphertext_blocks.append(blowfish.blowfish_on_64_bits(plaintext_blocks[i],  # Run blowfish on each plaintext
                                                              p_array, s_boxes))    # block
        print("Encrypting: " + str((i / len(plaintext_blocks)) * 100)               # Print updates
                + "%")


    # Run cbc
    iv, key = _generate_key_w_iv(key, encoding_scheme)              # Get iv and the new key
    ciphertext_blocks = _conduct_cbc(ciphertext_blocks, iv)         # Run the cbc



    # Turn the blocks of ints into blocks of characters with encoding scheme. Then, concatenate for final ciphertext
    ciphertext_blocks = [ misc.int_to_chars_encoding_scheme_pad(block, encoding_scheme, 64)    # Each block is 64 bits
                                                            for block in ciphertext_blocks]
    for block in ciphertext_blocks:                                                            # Concatenate blocks
        ciphertext += block
    blowfish_cbc.testing_execute.num_blocks = len(ciphertext_blocks)    # Save block info into Decryption's blowfish_cbc

    blowfish_cbc.testing_execute.block_size = len(ciphertext_blocks[0])



    # Return the ciphertext and the generated key
    return ciphertext, key








######################################################################################### ANCILLARY FUNCTIONS ##########

# Generate a new key that uses IV
def _generate_key_w_iv(key:int, encoding:str) -> (int, str):
    """
    This function generates an IV to be used during CBC. In addition, the IV is encoded and concatenated with the
    given blowfish key.

    :param key:      (int) key used during the regular blowfich encryption
    :param encoding: (str) the name of the encoding to use
    :return:         (int) the IV
    :return:         (str) the character encoded IV concatenated with the old key. This is the new key
    """


    # Generate a random IV (should be 64 bits, same size as the blocks)
    iv = secrets.randbits(64)


    # Character encode the iv and key.
    char_iv = misc.int_to_chars_encoding_scheme_pad(iv, encoding, 64)
    key = misc.int_to_chars_encoding_scheme(key, encoding)

    # Concatenate the string iv to the old non-cbc blowfish key
    new_key = char_iv + key

    # Return
    return iv, new_key



# Conduct the cbc
def _conduct_cbc(blocks:list, iv:int) -> list:
    """
    Conduct cbc on the blowfish-encrypted blocks with the given IV

    :param blocks: (list) list of integers. The blowfish encrypted blocks.
    :param iv:     (int)  the iv to start cbc with
    :return:
    """


    cbc_blocks = []                                           # Build up the cbc here


    # XOR the first block with the iv
    cbc_blocks.append(blocks[0] ^ iv)


    # Chain the rest of the blocks
    for i in range (1, len(blocks)):

        # XOR the current block with the previous block. Save in the cbc_blocks
        xor_result = blocks[i] ^ blocks[i - 1]
        cbc_blocks.append(xor_result)


    # Return result
    return cbc_blocks





