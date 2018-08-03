from Cryptography.Ciphers import _cipher    # For abstract superclass
from Cryptography         import misc               # For miscellaneous functions











class Rotation(_cipher.Cipher):

    # Cipher info:
    CIPHER_NAME         = "Rotation using Modular Addition"
    CHAR_SET            = "alphabet"
    CIPHER_TYPE         = "symmetric"
    KEY_TYPE            = "single character"
    RESTRICT_ALPHABET   = True
    NEEDS_ENGLISH       = False
    VARIABLE_BLOCK_SIZE = False
    DEFAULT_BLOCK_SIZE  = 0



    # Constructor
    def __init__(self, plaintext="", ciphertext="", char_set="", mode_of_operation="", key="", public_key="",
                       private_key="", block_size=0, key_size=0, source_location="", output_location="") -> None:
        super().__init__(plaintext,  ciphertext,    char_set,                      "",    key,            "",
                                   "",            0,          0, source_location,    output_location)


    # Algorithm to encrypt plaintext
    def encrypt_plaintext(self, plaintext="", key="", alphabet=""):
        """
        This encrypts with a rotation cipher (using modular addition) and fills in self.ciphertext

        :param plaintext: (str) The plaintext to encrypt
        :param key:       (str) The single-character key to encrypt with
        :param alphabet:  (str) The name of the alphabet to use
        :return:          (str) The encrypted ciphertext
        """

        # Fill out parameters
        plaintext  = self.plaintext
        key        = self.key
        alphabet   = self.char_set

        # Other important variables
        ciphertext    = []                                # The list to build up the ciphertext, one character at a time
        alphabet_size = misc.ALPHABETS.get(alphabet)      # The size of the alphabet (used as modulus)


        # Encrypt every single character in the plaintext
        for char in plaintext:

            plain_val = ord(char)   # The unicode value for the current plaintext char
            key_val   = ord(key[0]) # Figure out the unicode value of the key character


            # Figure out the encrypted character val
            encrypted_char = chr((plain_val + key_val) % alphabet_size)
            ciphertext.append(encrypted_char)


        # Concatenate all the characters in the list into one string
        ciphertext = "".join(ciphertext)

        # Set the self object's ciphertext
        self.ciphertext = ciphertext

        return






    # Algorithm to decrypt plaintext
    def decrypt_ciphertext(self, ciphertext="", key="", alphabet=""):
        """
        This decrypts with a rotation cipher (using modular subtraction)

        :param ciphertext: (str) The ciphertext to encrypt
        :param key:        (str) The single-character key to decrypt with
        :param alphabet:   (str) The name of the alphabet to use
        :return:           (str) The decrypted plaintext
        """

        # Fill out parameters
        ciphertext = self.ciphertext
        key        = self.key
        alphabet   = self.char_set

        # Other important variables
        plaintext = []                                    # The list to build up the ciphertext, one character at a time
        alphabet_size = misc.ALPHABETS.get(alphabet)      # Size of alphabet (used as modulus)

        # Decrypt every single character in the ciphertext
        for char in ciphertext:
            cipher_val = ord(char)  # The unicode value for the current ciphertext char
            key_val    = ord(key[0])  # Figure out the unicode value of the key character

            # Figure out the decrypted character val
            decrypted_char = chr((cipher_val - key_val) % alphabet_size)
            plaintext.append(decrypted_char)

        # Concatenate all the characters in the list into one string
        plaintext = "".join(plaintext)


        # Fill in self's plaintext
        self.plaintext = plaintext


        return






