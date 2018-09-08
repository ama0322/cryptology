from Cryptography.Ciphers._cipher                import Cipher     # For abstract superclass
from typing                                      import Tuple      # For tuple type-hints
from Cryptography                 import misc    # For miscellaneous functions




class Rsa(Cipher):

    # Cipher info:
    CIPHER_NAME          = "RSA"
    CHAR_SET             = "encoding scheme"
    CIPHER_TYPE          = "asymmetric"
    KEY_TYPE             = "generated characters"

    # Block cipher info
    IS_BLOCK_CIPHER      = True

    VARIABLE_KEY_SIZE    = True
    PROMPT_KEY_SIZE      = "The key's size must be 32—∞ bits"
    EXPRESSION_KEY_SIZE  = "32 <= key_size"
    DEFAULT_KEY_SIZE     = 1999
    AUTO_TEST_KEY_SIZE   = 32

    VARIABLE_BLOCK_SIZE      = False          # Don't ask for block_size, it is based on key_size
    DIFF_KEY_SIZE_BLOCK_SIZE = 1              # Block sizes are one bit smaller than the key size
    DEFAULT_BLOCK_SIZE       = DEFAULT_KEY_SIZE   - DIFF_KEY_SIZE_BLOCK_SIZE
    AUTO_TEST_BLOCK_SIZE     = AUTO_TEST_KEY_SIZE - DIFF_KEY_SIZE_BLOCK_SIZE

    # Restrictions
    RESTRICT_ALPHABET    = False
    NEEDS_ENGLISH        = False





    # Constructor
    def __init__(self, plaintext:str, ciphertext:str, char_set:str, mode_of_op:str, key:str, public_key:str,
                    private_key:str, block_size:int, key_size:int, source_location:str, output_location:str) -> None:

        # If the key_size is impossible (from test), then use the default
        if eval(self.EXPRESSION_KEY_SIZE) is False:
            key_size = Rsa.DEFAULT_KEY_SIZE

        # Figure out what the block_size is
        block_size = key_size - Rsa.DIFF_KEY_SIZE_BLOCK_SIZE

        super().__init__(plaintext,   ciphertext,      char_set,     mode_of_op,     "",      public_key,
                    private_key,     block_size,      key_size,     source_location,     output_location    )




    # Algorithm to encrypt plaintext
    @misc.process_times("self.encrypt_time_for_algorithm", "self.encrypt_time_overall", "self.encrypt_time_for_key")
    @misc.static_vars(time_overall=0, time_algorithm=0, time_key=0)
    def encrypt_plaintext(self, plaintext="", public_key="", key_size=0, encoding="",
                                                                            mode_of_op="")  -> Tuple[str, str, str]:
        """
        This encrypts with an rsa cipher. The user can choose to either provide a public key, in which case that key
        will be used to encrypt, or to leave the public key blank, in which case a pair of asymmetric keys will be
        generated. In either case, the exponent for encryption is saved into the _rsa_on_blocK() as a static variable.

        :param plaintext:  (str) The plaintext to encrypt
        :param public_key: (str) The public key to use (If left empty, will generate own public/private key set)
        :param key_size:   (int) The size of the key
        :param encoding:   (str) The name of the encoding to use
        :param mode_of_op  (str) The name of mode of operation to use
        :return:           (str) The ciphertext
        :return:           (str) The public key
        :return:           (str) The private key
        """


        # Parameters for encryption (if not provided)
        if plaintext == "" and public_key == "" and key_size == 0 and encoding == "" and mode_of_op == "":
            plaintext   = self.plaintext
            public_key  = self.public_key
            private_key = self.private_key
            key_size    = self.key_size
            block_size  = self.block_size   # This is the bits in the message "m". Technically, block size is key_size
            encoding    = self.char_set
            mode_of_op  = self.mode_of_op

        # Parameters provided, still need to figure out block_size
        else:
            block_size = key_size - 1


        # Important variables for encryption
        public_key        = ""
        private_key       = ""
        plaintext_blocks  = misc.utf_8_to_int_blocks(plaintext, block_size)  # integer blocks of text
        ciphertext_blocks = []                                               # Encrypted integer blocks
        ciphertext        = ""                                               # The final ciphertext




        # Read/generate key
        public_key, private_key = Rsa._read_public_or_private_key(False, public_key, private_key, key_size, block_size,
                                                                                    encoding, mode_of_op)



        # Encrypt the text using the proper mode of encryption
        ciphertext_blocks, public_key, private_key = eval("misc.encrypt_{}_asymm(self, Rsa._rsa_on_block, "
                                                                                "plaintext_blocks, public_key, "
                                                                                "private_key, block_size, key_size)"
                                                          .format(mode_of_op))





        # Get the ciphertext from the encrypted integer blocks (pad up to key_size)
        ciphertext = misc.int_blocks_to_encoded_chars(ciphertext_blocks, encoding, key_size)


        # Save the ciphertext, key, and the num_blocks and chars_per_block, and keys
        self.public_key      = public_key
        self.private_key     = private_key
        self.ciphertext      = ciphertext
        self.num_blocks      = len(ciphertext_blocks)
        self.chars_per_block = len(ciphertext) / self.num_blocks



        # Return encryption results
        return ciphertext, public_key, private_key





    # Algorithm to decrypt ciphertext
    @misc.process_times("self.decrypt_time_for_algorithm", "self.decrypt_time_overall", "self.decrypt_time_for_key")
    @misc.static_vars(time_overall=0, time_algorithm=0, time_key=0)
    def decrypt_ciphertext(self, ciphertext="", private_key="", key_size=0, encoding="", mode_of_op="") -> str:
        """
        This method requires that the self object be given a private key. This private key is read for its exponent,
        which is set as a static variable in the class function _rsa_on_block().

        :param ciphertext  (str) The ciphertext to decrypt
        :param private_key (str) The key to decrypt with
        :param key_size    (int) The size of the key
        :param encoding    (str) The name of the encoding to use
        :param mode_of_op  (str) The name of the mode of operation to use
        :return:           (str) The decrypted plaintext
        """


        # Parameters for encryption (if not provided)
        if ciphertext == "" and private_key == "" and key_size == 0 and encoding == "" and mode_of_op == "":
            ciphertext  = self.ciphertext
            public_key  = self.public_key
            private_key = self.private_key
            key_size    = self.key_size
            block_size  = self.block_size
            encoding    = self.char_set
            mode_of_op  = self.mode_of_op

        # Parameters provided, but need additional info
        else:
            block_size = key_size - 1
            public_key = ""


        # Important variables for decryption
        ciphertext_blocks = misc.encoded_chars_to_int_blocks(ciphertext, encoding, key_size)  # Use KEY_SIZE, not BLOCK
        plaintext_blocks  = []
        plaintext         = ""



        # Read the private key
        public_key, private_key = Rsa._read_public_or_private_key(True, public_key, private_key, key_size,
                                                                   block_size, encoding, mode_of_op)



        # Decrypt the text using the proper mode of encryption
        plaintext_blocks, public_key, private_key = eval("misc.decrypt_{}_asymm(self, Rsa._rsa_on_block, "
                                                                               "ciphertext_blocks, "
                                                                               "public_key, private_key, "
                                                                               "block_size, key_size)"
                                                         .format(self.mode_of_op))



        # Get the plaintext from the encrypted integer blocks
        plaintext = misc.int_blocks_to_utf_8(plaintext_blocks, block_size)




        # Save the ciphertext, key, and the num_blocks and chars_per_block
        self.plaintext       = plaintext
        self.public_key      = public_key
        self.private_key     = private_key
        self.num_blocks      = len(plaintext_blocks)
        self.chars_per_block = len(plaintext) / self.num_blocks


        # Return plaintext
        return plaintext






    # Write to the file about the statistics of the file (Call super-method)
    def write_statistics(self, file_path:str, leave_empty={}) -> None:
        """
        Write statistics

        :param file_path:   (str)  The file to write the statistics in
        :param leave_empty: (dict) Exists to match superclass method
        :return:            (None)
        """

        super().write_statistics(file_path)





    ##################################################################################### ANCILLARY FUNCTIONS ##########




    # Returns: encrypted_block. The actual algorithm run on a 64-bit integer block.
    @staticmethod
    @misc.static_vars(exponent=0, modulus=0)         # Needs to be set by _key_schedule() before call
    def _rsa_on_block(block:int) -> int:
        """
        This is algorithm that runs on the integer block

        :param block:   (int) the block to encrypt/decrypt
        :return:        (int) the encrypted/decrypted result
        """

        the_exponent = Rsa._rsa_on_block.exponent
        the_mod = Rsa._rsa_on_block.modulus


        return pow(block, Rsa._rsa_on_block.exponent, Rsa._rsa_on_block.modulus)





    # Reads key (accounts for mode of op) and runs the key gen, which sets static_vars in _blowfish_on_block
    @staticmethod
    @misc.add_time_in("Rsa.encrypt_plaintext.time_key", "Rsa.decrypt_ciphertext.time_key")
    def _read_public_or_private_key(is_decrypt:bool, public_key:str, private_key:str, key_size:int,
                                    block_size:int, encoding:str, mode_of_op:str) -> (str, str):
        """
    	Reads the key. If it is a public key and is empty (""), then generate own pair of public and private keys.
    	Otherwise, read the key and set the exponent in _rsa_on_block().

        :param is_decrypt   (bool) If in decrypt mode
        :param public_key:  (str)  The public key to read. May be empty during encryption
        :param private_key: (str)  The private key to read. Is NEVER empty during decryption
        :param key_size     (int)  The size of the key for generation (if needed)
        :param block_size   (int)  The size of the IV is block_size + 1
        :param encoding:    (str)  The name of the encoding scheme used
        :param mode_of_op:  (str)  The name of the mode operation to be used
    	:return:            (str)  The public key
    	:return:            (str)  The private key
    	"""


        # If both the public_key and private_key are empty, then generate own pair of public/private keys
        if private_key == "" and public_key == "":

            # Create and return the public and private keys
            public_key, private_key = Rsa._generate_public_and_private_keys(key_size, encoding)




        # Either or both the public_key or private_key is filled in. So read and use that key
        elif private_key != "" or public_key !="":

            # Set key to whichever one we are using (prefer private_key b/c testing)
            if private_key != "":
                key = private_key
            else:
                key = public_key

            # If in a mode that uses IV—everything other than ECB—then cut out the part that uses the IV.
            if is_decrypt is True and mode_of_op != "ecb":

                # Cut out the part of the key that is relevant to the IV
                len_to_skip = len(misc.int_to_chars_encoding_scheme_pad(1, encoding, block_size))
                key = key[len_to_skip:]


            # Decode the key to format: "RSA (character length of e or d) (e or d) n"
            key = misc.chars_to_chars_decoding_scheme(key, encoding)

            # Figure out how many characters to read for the exponent d/e. From the first space to the second. Convert
            first_space_index = key.find(" ")
            second_space_index = key.find(" ", first_space_index + 1)
            length = key[first_space_index + 1: second_space_index]
            length = int(length, 10)

            # Read length characters to figure out e/d and also n. Decode them into ints
            exponent = key[second_space_index + 1: second_space_index + 1 + length]
            n = key[second_space_index + 1 + length:]
            exponent = misc.chars_to_int_decoding_scheme(exponent, encoding)
            n = misc.chars_to_int_decoding_scheme(n, encoding)


            # Set the exponent and modulus in _rsa_on_block()
            Rsa._rsa_on_block.exponent = exponent
            Rsa._rsa_on_block.modulus = n



        # Return
        return public_key, private_key





    # Generates a public and private key. Sets static_var exponent in _rsa_on_block() to be used for ENCRYPTION
    @staticmethod
    def _generate_public_and_private_keys(key_size:int, encoding_scheme: str) -> (str, str):
        """
        Given two primes, calculate the private and public key

        :param key_size         (int) The size of the key to generate (primes are about half of these)
        :param encoding_scheme: (str) tells us which encoding to use to render the public/private keys as text
        :return:                (str) public key in format "e = ..., n = ..."
        :return:                (str) private key in format "d = ..., n = ..."
        """


        prime_one, prime_two = misc.generate_prime_pair(key_size)



        modulus = prime_one * prime_two                      # Calculate modulus by multiplying the two primes
        modulus_totient = (prime_one - 1) * (prime_two - 1)  # Calculate totient speedily(using properties of primes)

        e = 65537  # Commonly used as e for low hamming weight, among other reasons


        # Calculate d (modular multiplicative inverse of (e mod n). Compute with extended euclidean algorithm
        d = misc.mod_inverse(e, modulus_totient)


        # Set the exponent and modulus in (Decryption).rsa._rsa_on_block()
        Rsa._rsa_on_block.exponent = e
        Rsa._rsa_on_block.modulus = modulus

        # Convert d  and e, and modulus from numbers to encoded character version. Also do e and d's lengths
        e = misc.int_to_chars_encoding_scheme(e, encoding_scheme)
        e_len = len(e)
        d = misc.int_to_chars_encoding_scheme(d, encoding_scheme)
        d_len = len(d)
        modulus = misc.int_to_chars_encoding_scheme(modulus, encoding_scheme)

        # Build up the public and private keys strings. Then encode them using whichever scheme
        public_key = "RSA: " + str(e_len) + " " + e + modulus
        private_key = "RSA: " + str(d_len) + " " + d + modulus
        public_key = misc.chars_to_chars_encoding_scheme(public_key, encoding_scheme)
        private_key = misc.chars_to_chars_encoding_scheme(private_key, encoding_scheme)


        # Return the public and private keys
        return public_key, private_key




















