from Cryptography.Ciphers._cipher             import Cipher     # For abstract superclass
from Cryptography                 import misc                   # For miscellaneous functions



class Vigenere(Cipher):

    # Cipher info:
    CIPHER_NAME         = "Vigenere using Modular Addition"
    CHAR_SET            = "alphabet"
    CIPHER_TYPE         = "symmetric"
    KEY_TYPE            = "multiple characters"

    IS_BLOCK_CIPHER      = False
    VARIABLE_BLOCK_SIZE  = False
    DEFAULT_BLOCK_SIZE   = 0
    AUTO_TEST_BLOCK_SIZE = 0

    VARIABLE_KEY_SIZE    = False
    DEFAULT_KEY_SIZE     = 0
    AUTO_TEST_KEY_SIZE   = 0

    RESTRICT_ALPHABET   = True
    NEEDS_ENGLISH       = False


    # Constructor
    def __init__(self, plaintext:str, ciphertext:str, char_set:str, mode_of_op:str, key:str, public_key:str,
                    private_key:str, block_size:int, key_size:int, source_location:str, output_location:str) -> None:

        super().__init__(plaintext,   ciphertext,     char_set,     "",     key,                    "",
                    "",              0,              0,            source_location,     output_location    )



    # Algorithm to encrypt plaintext
    @misc.store_time_in("self.encrypt_time_overall", "self.encrypt_time_for_algorithm")
    def encrypt_plaintext(self, plaintext="", key="", alphabet="") -> str:
        """
        This works like rotation, but cycles the letters of the key used. So, the first character is encrypted with
        the first letter, the second character with the second letter, and so on. When we run out of characters in
        the key, just start the cycle from the first key again.

        :param plaintext: (str) The plaintext to encrypt
        :param key:       (str) The key to encrypt with
        :param alphabet:  (str) The name of the character set to encrypt into
        :return:          (str) The encrypted ciphertext
        """

        # Parameters for encryption (if not provided)
        if plaintext == "" and key == "" and alphabet == "":
            plaintext  = self.plaintext
            key        = self.key
            alphabet   = self.char_set

        # Other important variables
        ciphertext    = []                              # The list to build up the ciphertext, one character at a time
        alphabet_size = Cipher.ALPHABETS.get(alphabet)  # The size of the alphabet (used as modulus)
        key_index     = 0                               # Index for the vigenere key. Starts from 0


        # Encrypt every single character in the plaintext
        for i in range(0, len(plaintext)):

            plain_val = misc.ord_adjusted(plaintext[i])            # The unicode value for the current plaintext char
            key_val   = misc.ord_adjusted(key[key_index])          # Figure out the unicode value of the key character
            key_index = (key_index + 1) % len(key)                 # Update the key index

            # Figure out the encrypted character val
            encrypted_char = misc.chr_adjusted((plain_val + key_val) % alphabet_size)
            ciphertext.append(encrypted_char)

            # Print updates
            if i % misc.utf_8_to_int_blocks.update_interval == 0:
                print("Encryption percent done: {}{:.2%}{}"
                      .format("\u001b[32m",
                              i / len(plaintext),
                              "\u001b[0m"))


        # Concatenate all the characters in the list into one string
        ciphertext = "".join(ciphertext)

        # Set the self object's ciphertext
        self.ciphertext = ciphertext



        # Return ciphertext
        return ciphertext





    # Algorithm to decrypt plaintext
    @misc.store_time_in("self.decrypt_time_overall", "self.decrypt_time_for_algorithm")
    def decrypt_ciphertext(self, ciphertext="", key="", alphabet="") -> str:
        """
        This does the same thing as encrypt, but modularly subtracts to do the reversal.

        :param ciphertext: (str) The ciphertext to decrypt
        :param key:        (str) The key to decrypt with
        :param alphabet:   (str) The name of the alphabet to use
        :return:           (str) The decrypted plaintext
        """

        # Parameters for decryption (if not provided)
        if ciphertext == "" and key == "" and alphabet == "":
            ciphertext = self.ciphertext
            key        = self.key
            alphabet   = self.char_set

        # Other important variables
        plaintext     = []                              # The list to build up the ciphertext, one character at a time
        alphabet_size = Cipher.ALPHABETS.get(alphabet)    # Size of alphabet (used as modulus)
        key_index     = 0                               # Index for the vigenere key. Starts from 0

        # Decrypt every single character in the ciphertext
        for i in range(0, len(ciphertext)):
            cipher_val = misc.ord_adjusted(ciphertext[i])         # The unicode value for the current ciphertext char
            key_val    = misc.ord_adjusted(key[key_index])        # Figure out the unicode value of the key character
            key_index  = (key_index + 1) % len(key)               # Update the key_index

            # Figure out the decrypted character val
            decrypted_char = misc.chr_adjusted((cipher_val - key_val) % alphabet_size)
            plaintext.append(decrypted_char)


            # Print updates
            if i % misc.utf_8_to_int_blocks.update_interval == 0:
                print("Decryption percent done: {}{:.2%}{}"
                      .format("\u001b[32m", i / len(ciphertext), "\u001b[0m"))


        # Concatenate all the characters in the list into one string
        plaintext = "".join(plaintext)


        # Fill in self's plaintext
        self.plaintext = plaintext


        # Return plaintext
        return plaintext





    # Write to the file about the statistics of the file (Call super-method)
    def write_statistics(self, file_path:str, leave_empty={}) -> None:
        """
        Write statistics

        :param file_path:   (str)  The file to write the statistics in
        :param leave_empty: (dict) Exists to match superclass method signature
        :return:            (None)
        """
        super().write_statistics(file_path)



































