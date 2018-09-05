from Cryptography.Ciphers._cipher             import Cipher     # For abstract superclass
from Cryptography                 import misc                   # For miscellaneous functions
import                                   secrets                # To generate random key



class Aes(Cipher):

    # Cipher info:
    CIPHER_NAME         = "AES"
    CHAR_SET            = "encoding scheme"
    CIPHER_TYPE         = "symmetric"
    KEY_TYPE            = "generated characters"

    # Block info
    IS_BLOCK_CIPHER      = True

    VARIABLE_KEY_SIZE    = True
    PROMPT_KEY_SIZE      = "The key's size must be 128, 192, or 256 bits"
    EXPRESSION_KEY_SIZE  = "key_size == 128 or key_size == 192 or key_size == 256"
    DEFAULT_KEY_SIZE     = 256
    AUTO_TEST_KEY_SIZE   = 128

    VARIABLE_BLOCK_SIZE  = False
    DEFAULT_BLOCK_SIZE   = 128
    AUTO_TEST_BLOCK_SIZE = 128


    # Restrictions
    RESTRICT_ALPHABET   = False
    NEEDS_ENGLISH       = False





    # Cipher Resources
    s_box = [
        # region Rijndael Substitution box
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        # endregion
    ]

    mul_2 = [
        # region Lookup table for multiplication by 2
        0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
        0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
        0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
        0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
        0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
        0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
        0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
        0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
        0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
        0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
        0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
        0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
        0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
        0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
        0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
        0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
        # endregion
    ]

    mul_3 = [
        # region Lookup table for multiplication by 3
        0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
        0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
        0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
        0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
        0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
        0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
        0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
        0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
        0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
        0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
        0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
        0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
        0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
        0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
        0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
        0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a
        # endregion
    ]



    # Constructor
    def __init__(self, plaintext:str, ciphertext:str, char_set:str, mode_of_op:str, key:str, public_key:str,
                    private_key:str, block_size:int, key_size:int, source_location:str, output_location:str) -> None:

        # If the key_size is impossible (from test), then use the default
        if eval(self.EXPRESSION_KEY_SIZE) is False:
            key_size = Aes.DEFAULT_KEY_SIZE

        # Blowfish uses a block_size of 128
        block_size = Aes.DEFAULT_BLOCK_SIZE

        super().__init__(plaintext,   ciphertext,     char_set,     mode_of_op,     key,     "",
                    "",              block_size,     key_size,     source_location,     output_location    )




    # Algorithm to encrypt plaintext
    @misc.get_time_for_algorithm("self.encrypt_time_for_algorithm", "self.encrypt_time_overall",
                                 "self.encrypt_time_for_key")
    @misc.store_time_in("self.encrypt_time_overall")
    def encrypt_plaintext(self) -> None:
        """
        This encrypts with a blowfish cipher. Like all block ciphers, the plaintext is changed into 64-bit integer
        blocks. Then, the key schedule is run with a randomly generated key, which sets the "true" key, the p_array and
        s_boxes static variables in the _blowfish_on_block() function.

        :return:          (None)
        """

        # Parameters for encryption
        plaintext  = self.plaintext
        key        = self.key
        key_size   = self.key_size
        encoding   = self.char_set
        mode_of_op = self.mode_of_op


        # Important variables for encryption
        plaintext_blocks = misc.utf_8_to_int_blocks(plaintext, Aes.DEFAULT_BLOCK_SIZE)   # integer blocks of text
        ciphertext_blocks = []                                                               # Encrypted integer blocks
        ciphertext = ""                                                                      # The final ciphertext



        pass







    # Algorithm to decrypt ciphertext
    @misc.get_time_for_algorithm("self.decrypt_time_for_algorithm", "self.decrypt_time_overall",
                                 "self.decrypt_time_for_key")
    @misc.store_time_in("self.decrypt_time_overall")
    def decrypt_ciphertext(self) -> None:
        """
        As with all block ciphers, the ciphertext is split into 64-bit integer blocks. This method needs a given key,
        which is read to be used for the key schedule. Blowfish decryption is exactly the same as the encryption,
        except that the p_array must be reversed.

        :return:           (None)
        """

        # Parameters for encryption
        ciphertext = self.ciphertext
        key        = self.key
        key_size   = self.key_size
        encoding   = self.char_set
        mode_of_op = self.mode_of_op


        # Important variables for decryption
        ciphertext_blocks = misc.encoded_chars_to_int_blocks(ciphertext, encoding, Aes.DEFAULT_BLOCK_SIZE)
        plaintext_blocks = []
        plaintext = ""



        pass






    # Write to the file about the statistics of the file (Call super-method)
    def write_statistics(self, file_path:str, leave_empty={}) -> None:
        """
        Write statistics

        :param file_path:   (str)  The file to write the statistics in
        :param leave_empty: (dict) Exists to match superclass method signature
        :return:            (None)
        """

        super().write_statistics(file_path)





    ##################################################################################### ANCILLARY FUNCTIONS ##########




    # Returns: encrypted_block. The actual algorithm run on a 64-bit integer block.
    @staticmethod
    @misc.static_vars(round_keys=[])                          # Round keys must be set by _key_schedule()
    def _aes_on_block(block:int) -> int:
        """
        This is algorithm that runs on the 128-bit integer blocks

        :param block:   (int) the 128-bit block of plaintext to encrypt/decrypt
        :return:        (int) the encrypted/decrypted result
        """

        def sub_bytes(state:list) -> list:
            """
            This performs a substitution on the bytes of the state, using the Rijndael s_box. The state is a
            list of one-byte ints.

            :param state: (list) the current state to be substituted with
            :return:      (list) the substituted result
            """
            for i in range(0, len(state)):
                state[i] = Aes.s_box[ state[i] ]

            return state

        def shift_rows(state:list) -> list:
            """
            The state is treated as a grid, starting from the top left, and laid out from top to bottom,
            and then left to right when out of space. The second layer is rotated to the left one byte,
            the third layer two bytes, and the fourty layer three bytes.

            :param state: (list) The current state during the cipher
            :return:      (list) The result after the shifting of the rows
            """

            # Create a new_state, which will be filled in by the actual state
            new_state = [0] * 16                    # Sixteen numbers, each number is one byte (128 bits total)

            new_state[0] = state[0]
            new_state[1] = state[5]
            new_state[2] = state[10]
            new_state[3] = state[15]

            new_state[4] = state[4]
            new_state[5] = state[9]
            new_state[6] = state[14]
            new_state[7] = state[3]

            new_state[8] = state[8]
            new_state[9] = state[13]
            new_state[10] = state[2]
            new_state[11] = state[7]

            new_state[12] = state[12]
            new_state[13] = state[1]
            new_state[14] = state[6]
            new_state[15] = state[11]


            return new_state

        def mix_columns(state:list) -> list:
            """
            Mix the columns of the current state

            :param state: (list) The list of bytes representing the state
            :return:      (list) The processed result
            """

            new_state = [0] * len(state)

            # Shorthand for the mul_2 and mul_3 static variables
            mul_2 = Aes.mul_2
            mul_3 = Aes.mul_3

            new_state[0] = mul_2[state[0]] ^ mul_3[state[1]] ^ state[2] ^ state[3]
            new_state[1] = state[0] ^ mul_2[state[1]] ^ mul_3[state[2]] ^ state[3]
            new_state[2] = state[0] ^ state[1] ^ mul_2[state[2]] ^ mul_3[state[3]]
            new_state[3] = mul_3[state[0]] ^ state[1] ^ state[2] ^ mul_2[state[3]]

            new_state[4] = mul_2[state[4]] ^ mul_3[state[5]] ^ state[6] ^ state[7]
            new_state[5] = state[4] ^ mul_2[state[5]] ^ mul_3[state[6]] ^ state[7]
            new_state[6] = state[4] ^ state[5] ^ mul_2[state[6]] ^ mul_3[state[7]]
            new_state[7] = mul_3[state[4]] ^ state[5] ^ state[6] ^ mul_2[state[7]]

            new_state[8] = mul_2[state[8]] ^ mul_3[state[9]] ^ state[10] ^ state[11]
            new_state[9] = state[8] ^ mul_2[state[9]] ^ mul_3[state[10]] ^ state[11]
            new_state[10] = state[8] ^ state[9] ^ mul_2[state[10]] ^ mul_3[state[11]]
            new_state[11] = mul_3[state[8]] ^ state[9] ^ state[10] ^ mul_2[state[11]]

            new_state[12] = mul_2[state[12]] ^ mul_3[state[13]] ^ state[14] ^ state[15]
            new_state[13] = state[12] ^ mul_2[state[13]] ^ mul_3[state[14]] ^ state[15]
            new_state[14] = state[12] ^ state[13] ^ mul_2[state[14]] ^ mul_3[state[15]]
            new_state[15] = mul_3[state[12]] ^ state[13] ^ state[14] ^ mul_2[state[15]]


            # Return
            return new_state

        def add_round_key(state:list) -> list:
            """
            XOR each byte in the state with the corresponding byte in round_keys. This is actually a Galois addition,
            but calcultes the same as XOR.

            :param state: (list) The list of bytes representing the state
            :return:      (list) The processed result
            """

            for i in range(0, len(state)):
                state[i] ^= Aes._aes_on_block.round_keys[i]

            return state

        # Important variables
        state                  = []                  # Store the state here
        e_state                = []                  # The state after encryption is done (in list form)
        e_block                = 0                   # Store the encrypted block here
        key_size_to_num_rounds = {8:9, 12:11, 16:13} # Mappings from key_size (in bytes) to number of rounds
        num_rounds             = key_size_to_num_rounds.get(Aes._aes_on_block.round_keys.size())


        # Convert the 128-bit integer into 16 bytes (Convert into 128 length string for ease)
        bit_str = bin(block)[2:]                 # Remove the leading "0b"
        for i in range(0, 127, 8):               # Read the bitstring eight bits at a time (one byte)
            state.append(int(bit_str[i: i + 8]))     # Store the byte into the state


        # Initial round key addition
        state = add_round_key(state)


        # Run rounds however many times is necessary
        for i in range(0, num_rounds):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state)


        # Final round (Same as other rounds but skip mix_columns() step)
        state = sub_bytes(state)
        state = shift_rows(state)
        e_state = add_round_key(state)


        # Convert the state in list form to integer form
        e_block = ""                       # First, turn to binary string
        for i in range(len(e_state)):
            e_block += e_state[i]
        encrypted_block = int(e_block, 2)  # Turn the binary string into an integer




        return e_block






    # Expand the given key.
    @misc.store_time_in("self.encrypt_time_for_key", "self.decrypt_time_for_key")
    def _key_schedule(self, key:int) -> None:
        """
        Key setup for blowfish

        :param key:     (int) The key used for the key schedule
        :return:        (int) the generated key in integer form
        """




        pass





    # Reads key (accounts for mode of operation) and runs the key schedule, which sets static_vars in _blowfish_on_block
    def _read_aes_key_and_run_key_schedule(self, is_decrypt:bool, key:str, encoding:str, mode_of_op:str) -> None:
        """
    	Reads the key. Skips over IV portion of the key, if it exists. Then, it runs the key schedule

        :param is_decrypt (bool) If in decrypting mode
        :param key:       (str) The key to read
        :param encoding:  (str) The character encoding used
        :param mode_of_op (str) The name of the mode of operation to use
    	:return:          (str) The new key, adjusted for mode_of_operation
    	"""


        # If encoding and if in a mode that uses IV—everything other than ECB—then cut out the part that uses the IV.
        if is_decrypt is True and mode_of_op != "ecb":

            # Cut out the part of the key that is relevant to the IV
            len_to_skip = len(misc.int_to_chars_encoding_scheme_pad(1, encoding, self.DEFAULT_BLOCK_SIZE))
            key = key[len_to_skip:]


        # Decode the key to get the actual twofish int key
        key = misc.chars_to_int_decoding_scheme(key, encoding)


        # Run the key schedule
        self._key_schedule(key)



        return None









