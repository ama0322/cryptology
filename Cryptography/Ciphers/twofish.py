from Cryptography.Ciphers._cipher             import Cipher     # For abstract superclass
from Cryptography                 import misc                   # For miscellaneous functions
import                                   secrets                # To generate random key



class Twofish(Cipher):

    # Cipher info:
    CIPHER_NAME         = "Twofish"
    CHAR_SET            = "encoding scheme"
    CIPHER_TYPE         = "symmetric"
    KEY_TYPE            = "generated characters"

    # Block info
    IS_BLOCK_CIPHER      = True

    VARIABLE_KEY_SIZE    = True
    PROMPT_KEY_SIZE      = "The key's size must be 128, 192, or 256 bits"
    EXPRESSION_KEY_SIZE  = "key_size == 128 or key_size == 192 or key_size == 256"
    DEFAULT_KEY_SIZE     = 256
    MIN_KEY_SIZE         = 0
    MAX_KEY_SIZE         = 0
    AUTO_TEST_KEY_SIZE   = 128

    VARIABLE_BLOCK_SIZE  = False
    DEFAULT_BLOCK_SIZE   = 128
    MIN_BLOCKS_SIZE      = 128
    MAX_BLOCK_SIZE       = 128
    AUTO_TEST_BLOCK_SIZE = 128


    # Restrictions
    RESTRICT_ALPHABET   = False
    NEEDS_ENGLISH       = False






    # Constructor
    def __init__(self, plaintext:str, ciphertext:str, char_set:str, mode_of_op:str, key:str, public_key:str,
                    private_key:str, block_size:int, key_size:int, source_location:str, output_location:str) -> None:

        # Blowfish uses a block_size of 128
        block_size = Twofish.DEFAULT_BLOCK_SIZE

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
        plaintext_blocks = misc.utf_8_to_int_blocks(plaintext, Twofish.DEFAULT_BLOCK_SIZE)   # integer blocks of text
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
        ciphertext_blocks = misc.encoded_chars_to_int_blocks(ciphertext, encoding, Twofish.DEFAULT_BLOCK_SIZE)
        plaintext_blocks = []
        plaintext = ""



        pass






    # Write to the file about the statistics of the file (Call super-method)
    def write_statistics(self, file_path:str) -> None:
        """
        Write statistics

        :param file_path:   (str)  The file to write the statistics in
        :return:            (None)
        """

        super().write_statistics_in_file(file_path, {})





    ##################################################################################### ANCILLARY FUNCTIONS ##########




    # Returns: encrypted_block. The actual algorithm run on a 64-bit integer block.
    @staticmethod
    @misc.static_vars()                                          # Needs to be set by _key_schedule() before call
    def _twofish_on_block(block:int) -> int:
        """
        This is algorithm that runs on the 128-bit integer blocks

        :param block:   (int) the 128-bit block of plaintext to encrypt/decrypt
        :return:        (int) the encrypted/decrypted result
        """



        pass




    # Key schedule setup for the algorithm. Sets static_vars in _blowfish_on_block
    @misc.store_time_in("self.encrypt_time_for_key", "self.decrypt_time_for_key")
    def _key_schedule(self, key:int) -> None:
        """
        Key setup for blowfish

        :param key:     (int) The key used for the key schedule
        :return:        (int) the generated key in integer form
        """




        pass





    # Reads key (accounts for mode of operation) and runs the key schedule, which sets static_vars in _blowfish_on_block
    def _read_twofish_key_and_run_key_schedule(self, is_decrypt:bool, key:str, encoding:str, mode_of_op:str) -> None:
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









