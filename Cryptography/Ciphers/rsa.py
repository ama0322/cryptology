from Cryptography.Ciphers._cipher                import Cipher     # For abstract superclass
from Cryptography                 import misc    # For miscellaneous functions
import                                   secrets # To generate random key
import                                   test    # To get MANUAL_TEST_KEY_SIZE


class Rsa(Cipher):

    # Cipher info:
    CIPHER_NAME          = "RSA"
    CHAR_SET             = "encoding scheme"
    CIPHER_TYPE          = "asymmetric"
    KEY_TYPE             = "generated characters"

    # Block cipher info
    IS_BLOCK_CIPHER      = True
    VARIABLE_BLOCK_SIZE  = False                 # Don't ask for block_size
    VARIABLE_KEY_SIZE    = True                  # Key size should be EVEN
    DEFAULT_KEY_SIZE     = 2048
    MIN_KEY_SIZE         = 44
    MAX_KEY_SIZE         = float("inf")
    AUTO_TEST_KEY_SIZE   = 256

    DEFAULT_BLOCK_SIZE   = DEFAULT_KEY_SIZE - 42   # Block_size is key_size - 42
    MIN_BLOCK_SIZE       = MIN_KEY_SIZE - 42       # Block_size is key_size - 42
    MAX_BLOCK_SIZE       = float("inf")            # Block_size is key_size - 42
    AUTO_TEST_BLOCK_SIZE = AUTO_TEST_KEY_SIZE - 42

    # Restrictions
    RESTRICT_ALPHABET    = False
    NEEDS_ENGLISH        = False





    # Constructor
    def __init__(self, plaintext:str, ciphertext:str, char_set:str, mode_of_op:str, key:str, public_key:str,
                    private_key:str, block_size:int, key_size:int, source_location:str, output_location:str) -> None:

        # If the key_size is impossible, then use the default
        if key_size < Rsa.MIN_KEY_SIZE:
            key_size = Rsa.DEFAULT_KEY_SIZE

        super().__init__(plaintext,   ciphertext,     char_set,     mode_of_op,     "",      public_key,
                    private_key,     key_size - 42,  key_size,     source_location,     output_location    )




    # Algorithm to encrypt plaintext
    @misc.get_time_for_algorithm("self.encrypt_time_for_algorithm", "self.encrypt_time_overall",
                                 "self.encrypt_time_for_key")
    @misc.store_time_in("self.encrypt_time_overall")
    def encrypt_plaintext(self) -> None:
        """
        This encrypts with an rsa cipher. The user can choose to either provide a public key, in which case that key
        will be used to encrypt, or to leave the public key blank, in which case a pair of asymmetric keys will be
        generated. In either case, the exponent for encryption is saved into the _rsa_on_blocK() as a static variable.

        :return:          (None)
        """


        # Parameters for encryption
        plaintext   = self.plaintext
        public_key  = self.public_key
        private_key = self.private_key
        key_size    = self.key_size
        block_size  = self.key_size - 42
        encoding    = self.char_set
        mode_of_op  = self.mode_of_op


        # Important variables for encryption
        public_key        = ""
        private_key       = ""
        plaintext_blocks  = misc.utf_8_to_int_blocks(plaintext, block_size)  # integer blocks of text
        ciphertext_blocks = []                                               # Encrypted integer blocks
        ciphertext        = ""                                               # The final ciphertext



        # Read/generate key
        public_key, private_key = self._read_public_or_private_key(False, public_key, private_key, key_size, block_size,
                                                                                    encoding, mode_of_op)



        # Encrypt the text using the proper mode of encryption
        ciphertext_blocks, public_key, private_key = eval("misc.encrypt_{}(self, Rsa._rsa_on_block, plaintext_blocks, "
                                                          "public_key, private_key)"
                                                          .format(mode_of_op))




        # Get the ciphertext from the encrypted integer blocks (pad up to key_size)
        ciphertext = misc.int_blocks_to_encoded_chars(ciphertext_blocks, encoding, key_size)


        # Save the ciphertext, key, and the num_blocks and chars_per_block, and keys
        self.public_key      = public_key
        self.private_key     = private_key
        self.ciphertext      = ciphertext
        self.num_blocks      = len(ciphertext_blocks)
        self.chars_per_block = len(ciphertext) / self.num_blocks


        # Return nothing
        return None





    # Algorithm to decrypt ciphertext
    @misc.store_time_in("self.decrypt_time_overall", "self.decrypt_time_for_algorithm")
    def decrypt_ciphertext(self) -> None:
        """
        This method requires that the self object be given a private key. This private key is read for its exponent,
        which is set as a static variable in the class function _rsa_on_block().

        :return:           (None)
        """


        # Parameters for encryption
        ciphertext  = self.ciphertext
        public_key  = self.public_key
        private_key = self.private_key
        key_size    = self.key_size
        block_size  = self.key_size - 42
        encoding    = self.char_set
        mode_of_op  = self.mode_of_op


        # Important variables for decryption
        ciphertext_blocks = misc.encoded_chars_to_int_blocks(ciphertext, encoding, key_size) # Was padded up to key_size
        plaintext_blocks  = []
        plaintext         = ""




        # Read the private key
        public_key, private_key = self._read_public_or_private_key(True, public_key, private_key, key_size,
                                                                   block_size, encoding, mode_of_op)




        # Decrypt the text using the proper mode of encryption
        plaintext_blocks, public_key, private_key = eval("misc.decrypt_{}(self, Rsa._rsa_on_block, ciphertext_blocks, "
                                                         "public_key, private_key)"
                                                         .format(self.mode_of_op))




        # Get the plaintext from the encrypted integer blocks
        plaintext = misc.int_blocks_to_utf_8(plaintext_blocks, block_size)




        # Save the ciphertext, key, and the num_blocks and chars_per_block
        self.plaintext       = plaintext
        self.public_key      = public_key
        self.private_key     = private_key
        self.num_blocks      = len(plaintext_blocks)
        self.chars_per_block = len(plaintext) / self.num_blocks


        # Return nothing
        return None






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
    def _read_public_or_private_key(self, is_decrypt:bool, public_key:str, private_key:str, key_size:int,
                                    block_size:int, encoding:str, mode_of_op:str) -> (str, str):
        """
    	Reads the key. If it is a public key and is empty (""), then generate own pair of public and private keys.
    	Otherwise, read the key and set the exponent in _rsa_on_block().

        :param is_decrypt   (bool) If in decrypt mode
        :param public_key:  (str)  The public key to read. May be empty during encryption
        :param private_key: (str)  The private key to read. Is NEVER empty during decryption
        :param key_size     (int)  The size of the key for generation (if needed)
        :param block_size   (int)  The size of the block (for reading IV's)
        :param encoding:    (str)  The name of the encoding scheme used
        :param mode_of_op:  (str)  The name of the mode operation to be used
    	:return:            (str)  The public key
    	:return:            (str)  The private key
    	"""


        # If both the public_key and private_key are empty, then generate own pair of public/private keys
        if private_key == "" and public_key == "":

            # Create and return the public and private keys
            public_key, private_key = self._generate_public_and_private_keys(key_size, encoding)




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
    @misc.store_time_in("self.encrypt_time_for_key", "self.decrypt_time_for_key")
    def _generate_public_and_private_keys(self, key_size:int, encoding_scheme: str) -> (str, str):
        """
        Given two primes, calculate the private and public key

        :param key_size         (int) The size of the key to generate (primes are about half of these)
        :param encoding_scheme: (str) tells us which encoding to use to render the public/private keys as text
        :return:                (str) public key in format "e = ..., n = ..."
        :return:                (str) private key in format "d = ..., n = ..."
        """

        # Calculate d (modular multiplicative inverse of (e mod n). Compute with extended euclidean algorithm
        def inverse(x: int, modulus: int) -> int:

            # Extended euclidean algorithm
            a, b, u = 0, modulus, 1
            while x > 0:
                # Figure out the integer quotient
                quotient = b // x

                # Update for next iteration
                x, a, b, u = b % x, u, x, a - (quotient * u)

            # Calculate the modular multiplicative inverse by a % m
            if b == 1:
                return a % modulus



        prime_one, prime_two = misc.generate_prime_pair(key_size)



        modulus = prime_one * prime_two                      # Calculate modulus by multiplying the two primes
        modulus_totient = (prime_one - 1) * (prime_two - 1)  # Calculate totient speedily(using properties of primes)

        e = 65537  # Commonly used as e for low hamming weight, among other reasons


        # Calculate d (modular multiplicative inverse of (e mod n). Compute with extended euclidean algorithm
        d = inverse(e, modulus_totient)


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





