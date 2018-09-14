from Cryptography.Ciphers._cipher             import Cipher     # For abstract superclass
from Cryptography                 import misc                   # For miscellaneous functions
import pyximport; pyximport.install()



class VigenereExponential(Cipher):

    # Cipher info:
    CIPHER_NAME         = "Vigenere using Modular Exponentiation"
    CHAR_SET            = "alphabet"
    CIPHER_TYPE         = "symmetric"
    KEY_TYPE            = "multiple characters"

    IS_BLOCK_CIPHER      = False
    VARIABLE_BLOCK_SIZE  = False
    AUTO_TEST_BLOCK_SIZE = 0

    VARIABLE_KEY_SIZE    = False
    DEFAULT_KEY_SIZE     = 0
    AUTO_TEST_KEY_SIZE   = 0

    RESTRICT_ALPHABET   = False
    NEEDS_ENGLISH       = False


    # Constructor
    def __init__(self, plaintext:str, ciphertext:str, char_set:str, mode_of_op:str, key:str, public_key:str,
                    private_key:str, block_size:int, key_size:int, source_location:str, output_location:str) -> None:

        super().__init__(plaintext,   ciphertext,     char_set,     "",                    key,     "",
                    "",              0,              0,            source_location,     output_location    )



    # Algorithm to encrypt plaintext
    @misc.process_times("self.encrypt_time_for_algorithm", "self.encrypt_time_overall", "self.encrypt_time_for_key")
    @misc.static_vars(time_overall=0, time_algorithm=0, time_key=0)
    def encrypt_plaintext(self, plaintext="", key="", alphabet="") -> str:
        """
        This follows a similar format to vigenere, but uses modular exponentiation instead of modular addition.
        However, because modular exponentiation is not reversible like modular addition in a very straightforward
        way, I must store the number of unicode values that give the same result as the plaintext character unicode
        value when the modular exponentiation is done. This is done so that the original plaintext character can be
        calculated without confusing it for other unicode values that just happen to coincide.

        :param plaintext: (str) The plaintext to encrypt
        :param key:       (str) The key to encrypt with
        :param alphabet:  (str) The name of the character set to encrypt into
        :return:          (str) The encrypted ciphertext
        """

        # Parameters for encryption (if not provided)
        if plaintext == "" and key == "" and alphabet == "":
            plaintext     = self.plaintext
            key           = self.key
            alphabet      = self.char_set
            alphabet_size = Cipher.ALPHABETS.get(alphabet)
        else:
            alphabet_size = Cipher.ALPHABETS.get(alphabet)


        # Important variables to use during encryption
        ciphertext           = []                           # Build up the ciphertext here, one character at time
        key_index            = 0                            # The key index to get the character to use in the key
        characters_encrypted = 0                            # The number of characters encrypted




        # For each character in plaintext
        for char in plaintext:

            # Print updates (every 100 characters)
            characters_encrypted += 1
            if characters_encrypted % 1000 == 0 or characters_encrypted == len(plaintext):
                print("ENCRYPTION\tPercent of text done: {}{}%{} with {} characters"
                      .format("\u001b[32m",
                              format((characters_encrypted / len(plaintext)) * 100, ".2f"),
                              "\u001b[0m",
                              "{:,}".format(characters_encrypted)))


            # Obtain the two unicode values to operate on
            plain_val   = misc.ord_adjusted(char)                  # Find unicode value of plaintext char
            key_val     = misc.ord_adjusted(key[key_index])        # Find unicode value of the key
            key_index   = (key_index + 1) % len(key)               # Update key index for next iteration


            # Figure out the encrypted character
            encrypted_val = pow(plain_val, key_val, alphabet_size)
            encrypted_char = misc.chr_adjusted(encrypted_val)

            # Obtain the number of overlaps that come before this one (this plain_val) and NOT including this one
            overlap_counter = 0
            for i in range(0, plain_val):
                # If it is an overlap character
                if pow(i, key_val, alphabet_size) == encrypted_val and i != plain_val:
                    overlap_counter += 1


            # Add the block of information to the ciphertext
            ciphertext.append("{}{} ".format(encrypted_char, overlap_counter))



        # Join the ciphertext
        ciphertext = "".join(ciphertext)

        # Set the self object's ciphertext
        self.ciphertext = ciphertext


        # Return ciphertext
        return ciphertext





    # Algorithm to decrypt plaintext
    @misc.process_times("self.decrypt_time_for_algorithm", "self.decrypt_time_overall", "self.decrypt_time_for_key")
    @misc.static_vars(time_overall=0, time_algorithm=0, time_key=0)
    def decrypt_ciphertext(self, ciphertext="", key="", alphabet="") -> str:
        """
        In order to reverse the modular exponentiation, I have to test unicode values by applying the modular
        exponentiation with the key's unicode value to see if it matches the ciphertext value. However, because there
        may be coincidences in which unicode values which are not the original plaintext character's unicode value, I
        must take into account the number of overlaps, which was calculated during encryption. So, when I test values
        up from 0, I can stop when I reach the number of overlaps, indicating that I had reached the original value.

        :param ciphertext: (str) The ciphertext to decrypt
        :param key:        (str) The key to decrypt with
        :param alphabet:   (str) The name of the alphabet to use
        :return:           (str) The decrypted plaintext
        """

        # Parameters for decryption (if not provided)
        if ciphertext == "" and key == "" and alphabet == "":
            ciphertext    = self.ciphertext
            key           = self.key
            alphabet      = self.char_set
            alphabet_size = Cipher.ALPHABETS.get(alphabet)
        else:
            alphabet_size = Cipher.ALPHABETS.get(alphabet)


        # Other important variables
        plaintext            = []                           # Build up the plaintext here, one character at a time
        key_index            = 0                            # The key index to get the character to use in the key
        characters_decrypted = 0                            # The number of characters encrypted
        ciphertext_index     = 0                            # An index used for reading the ciphertext



        # While not finished processing ciphertext. Will be processing one block/unit at a time
        while ciphertext_index < len(ciphertext):

            # Print updates (every 100 characters)
            characters_decrypted += 1
            if characters_decrypted % 1000 == 0 or characters_decrypted == len(self.plaintext):
                print("DECRYPTION\tPercent of text done: {}{}%{} with {} characters"
                      .format("\u001b[32m",
                              format((characters_decrypted / len(self.plaintext)) * 100, ".2f"),
                              "\u001b[0m",
                              "{:,}".format(characters_decrypted)))


            # Read in one block/unit (one char, followed by a number, followed by a space). Then, update ciphertext
            next_space_index = ciphertext.find(" ", ciphertext_index + 1)
            char = ciphertext[ciphertext_index]
            num_to_reach = int(ciphertext[ciphertext_index + 1: next_space_index], 10)
            ciphertext_index = next_space_index + 1



            # Get important variables
            cipher_val = misc.ord_adjusted(char)                  # The unicode value for the current ciphertext char
            key_val    = misc.ord_adjusted(key[key_index])        # Figure out the unicode value of the key character
            key_index  = (key_index + 1) % len(key)               # Update the key_index


            # Find the original plain char by taking all possibilities and multiplying with key_val for a match
            overlap_counter = 0
            plain_char = "\0"
            for i in range(0, 1114112):

                # If overlap(count has not yet reached number)
                if pow(i, key_val, alphabet_size) == cipher_val:
                    if overlap_counter != num_to_reach:           # Not at the right plaintext char yet
                        overlap_counter += 1
                        continue
                    else:                                         # At the right plaintext char
                        plain_char = misc.chr_adjusted(i)
                        break

            # Add plain char to plaintext
            plaintext.append(plain_char)



        # Join the ciphertext
        plaintext = "".join(plaintext)

        # Save plaintext in self object
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
