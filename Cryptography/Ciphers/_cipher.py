from abc                      import ABC, abstractmethod # To create abstract classes









class Cipher(ABC):

    DECRYPTION_SET = {"blowfish", "rotation", "rotation_unknown", "rsa", "vigenere", "vigenere_exponential",
                      "vigenere_multiplicative"}
    ENCRYPTION_SET = {"blowfish", "rotation", "rsa", "vigenere", "vigenere_exponential", "vigenere_multiplicative"}

    ALPHABETS = {"ascii": 128, "extended_ascii": 256, "unicode_plane0": 65536 - 2048, "unicode": 1114112 - 2048}

    ENCODING_SCHEMES = {"base16":16, "base32":32, "base64":64, "base85":85, "extended_ascii":256, "base4096":4096}

    MODES_OF_OPERATION = ["ecb", "cbc", "pcbc", "cfb", "ofb", "ctr"]

    ASYMMETRIC_MODES_OF_OPERATION = ["ecb", "cbc", "pcbc"]

    # Cipher info of the class of the particular instantiation (overridden when specific cipher object is created):
    CIPHER_NAME         = ""
    CHAR_SET            = ""
    CIPHER_TYPE         = ""
    KEY_TYPE            = ""

    IS_BLOCK_CIPHER     = False

    VARIABLE_BLOCK_SIZE = False
    DEFAULT_BLOCK_SIZE  = 0
    MIN_BLOCKS_SIZE     = 0
    MAX_BLOCK_SIZE      = 0
    TEST_BLOCK_SIZE     = 0

    VARIABLE_KEY_SIZE   = False
    DEFAULT_KEY_SIZE    = 0
    MIN_KEY_SIZE        = 0
    MAX_KEY_SIZE        = 0
    AUTO_TEST_KEY_SIZE  = 0

    RESTRICT_ALPHABET   = False
    NEEDS_ENGLISH       = False

    # Constructor
    def __init__(self, plaintext:str, ciphertext:str, char_set:str, mode_of_op:str, key:str, public_key:str,
                 private_key:str, block_size:int, key_size:int, source_location:str, output_location:str) -> None:
        super().__init__()

        # Variables that detail the manner in which the encryption/decryption is done. Not all must be set
        self.plaintext         = plaintext         # (str) The plaintext
        self.ciphertext        = ciphertext        # (str) The ciphertext
        self.char_set          = char_set          # (str) The name of the character set to use
        self.mode_of_op        = mode_of_op        # (str) The name of the mode of operation to use

        self.key               = key               # (str) For symmetric ciphers, the symmetric key
        self.public_key        = public_key        # (str) For asymmetric ciphers, the public key
        self.private_key       = private_key       # (str) For asymmetric ciphers, the private key

        self.block_size        = block_size        # (int) For block ciphers, the size of the block
        self.key_size          = key_size          # (int) For block ciphers, the size of the key

        self.source_location   = source_location   # (str) The filepath of the source of the plaintext/ciphertext
        self.output_location   = output_location   # (str) The filepath of the output file

        # Variables that hold information about the encryption/decryption. Set these during/after encryption/decryption
        self.original_plaintext = self.plaintext   # (str)   The original plaintext, to compare with the decrypt result
        self.num_blocks         = 0                # (int)   The number of blocks used during encryption/decryption
        self.chars_per_block    = 0.0              # (float) Number of characters per block

        self.encrypt_time_overall       = 0.0      # (float) The overall time it takes for the encryption
        self.encrypt_time_for_algorithm = 0.0      # (float) The time_overall - time_for_key
        self.encrypt_time_for_key       = 0.0      # (float) The time it takes to handle keys (gene, schedule, ...)
        self.decrypt_time_overall       = 0.0      # (float) The overall time it takes for the decryption
        self.decrypt_time_for_algorithm = 0.0      # (float) The time_overall - time_for_key
        self.decrypt_time_for_key       = 0.0      # (float) The time it takes to handle keys (gen, schedule, ...)






    # The algorithm to encrypt plaintext
    @abstractmethod
    def encrypt_plaintext(self) -> None:
        """
        This encrypts the plaintext

        :return: (None)
        """
        pass


    # The algorithm to decrypt plaintext
    @abstractmethod
    def decrypt_ciphertext(self) -> None:
        """
        This decrypts the ciphertext

        :return: (None)
        """
        pass


    # Write to a file containing the statistics of encryption and decryption. extra_lines provided by subclass method.
    def write_statistics(self, file_path:str, extra_lines={}) -> None:
        """
        This writes the statistics into file_path. Extra_lines contains extra lines to write in in addition to the
        standard format

        :param file_path:   (str) The filepath to write in
        :param extra_lines: (dict) The dictionary containing the lines number to the string to write in
        :return:            (None)
        """

        # This function formats a list of strings to line up with the colon. The entire thing can be right-shifted
        def format_to_colon(lines: list, column=35) -> list:
            """
            This formats lines so that the colons line up. In addition, the entire thing can be right-shifted.

            :param lines:       (list) The list of strings to format
            :param column:      (int)  The column index where the colons should be. Overridden if too small
            :return:            (list) The list of formatted strings
            """

            # Figure out the index of the colon that is furthest out. Override with "column" parameter if necessary
            max_len = max(max(line.find(":") for line in lines), column)

            for i in range(0, len(lines)):
                if lines[i].find(":") == -1:  # If no colon in the line, then just skip
                    continue
                lines[i] = " " * (max_len - lines[i].find(":")) + lines[i]

            # return the new strings
            return lines

        # Figure out the character set of the given data automatically.
        # noinspection SpellCheckingInspection
        def get_char_set(data: str, cipher_char_set: str) -> str:
            """
            This calculates the character set of the given data automatically.

            :param data:            (str)  The data to analyze for char_set
            :param cipher_char_set: (str)  Either "alphabet" or "encoding scheme"
            :return:                (str)  The name of the char_set that the data is in
            """

            if cipher_char_set == "alphabet":
                # first pass through ciphertext, check if there are unicode characters (65536 and above)
                for x in data:
                    if ord(x) >= 65536:
                        return "unicode"

                # second pass through ciphertext, check if there are unicode_plane0
                for x in data:
                    if ord(x) >= 256:
                        return "unicode_plane0"

                # third pass through ciphertext, check if there are extended_ascii characters(128 and above)
                for x in data:
                    if ord(x) >= 128:
                        return "extended_ascii"

                # Otherwise, only ascii characters
                return "ascii"

            elif cipher_char_set == "encoding scheme":
                # If characters only in base16 char_set, return "base16"
                if all(character in "0123456789ABCDEF" for character in data):
                    return "base16"

                # Test base32 char_set
                if all(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for character in data):
                    return "base32"

                # Test base64 char_set
                if all(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                       for character in data):
                    return "base64"

                # Test base85 char_set
                if all(character in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>"
                                    "?@^_`{|}~"
                       for character in data):
                    return "base85"

                # Test ascii char_set
                if all(0 <= ord(character) < 128 for character in data):
                    return "extended_ascii"

                # Test extended_ascii char_set
                if all(0 <= ord(character) < 256 for character in data):
                    return "extended_ascii"

                # Else, is in base4096
                if all(0 <= ord(character) < 4096 for character in data):
                    return "base4096"






        # Open info file for writing
        stats_file = open(file_path, "w", encoding="utf-8")


        # Print out the "title" for the info_file
        lines = []
        lines.append("{} on {}".format(self.CIPHER_NAME, self.source_location))

        # Print out either "CORRECT" or "INCORRECT", (along with the number of incorrect chars if necessary)
        if self.original_plaintext == self.plaintext:
            num_diff_chars = sum(1 for a, b in zip(self.original_plaintext, self.plaintext) if a != b)
            lines.append("CORRECT\t\t\t\t\tPercent similarity: {}%\t\t\t\t\tCharacters different: {}"
                         .format(format(100 - ((num_diff_chars / len(self.original_plaintext)) * 100), ".2f"),
                                 num_diff_chars))
        else:
            num_diff_chars = sum(1 for a, b in zip(self.original_plaintext, self.plaintext) if a != b)
            lines.append("INCORRECT\t\t\t\t\tPercent similarity: {}%\t\t\t\t\tCharacters different: {}"
                         .format(format(100 - ((num_diff_chars / len(self.original_plaintext)) * 100), ".2f"),
                                 num_diff_chars))

        # Print out an area for notes, along with extra lines underneath that
        lines.append("Notes: ")
        lines.append(" ")
        lines.append(" ")

        # Print out "ENCRYPTION"
        lines.append("𝐄𝐍𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍")

        # Print out the key/public key
        if self.DEFAULT_BLOCK_SIZE == 0:                                           # If not a block cipher
            lines.append("―――――――― key ――――――――")
            lines.append("{}".format(self.key))
            lines.append("―" * 67)

        elif self.DEFAULT_BLOCK_SIZE != 0 and self.CIPHER_TYPE == "symmetric":    # Is a symmetric block cipher
            lines.append("―" * 67)
            lines.append("―――――――― {}-bit key ".format(self.key_size).ljust(73, "―"))
            lines.append("{}".format(self.key))
            lines.append(("――――――――"
                          + " {}(s) ".format(format(self.encrypt_time_for_key, ".20f")[0:len(str(self.key_size)) + 5]))
                            .ljust(73, "―"))
            lines.append("―" * 67)

        elif self.DEFAULT_BLOCK_SIZE != 0 and self.CIPHER_TYPE == "asymmetric":   # Is an asymmetric block cipher
            lines.append("―" * 67)
            lines.append("―――――――― {}-bit public key ".format(self.key_size).ljust(73 + 3, "―"))
            lines.append("{}".format(self.public_key))
            lines.append(("――――――――"
                          + " {}(s) ".format(format(self.encrypt_time_for_key,
                                                    ".20f")[0:len(str(self.key_size)) + 12]))
                            .ljust(73 + 3, "―"))
            lines.append("―" * 67)


        # Print out the encoding scheme/alphabet
        lines.append("The ciphertext's {} is: \"{}\"".format(self.CHAR_SET, self.char_set))

        # Print out the encryption time with characters (and blocks and characters per blocks if available)
        if self.CHAR_SET == "alphabet":
            lines.append("Encrypted in these seconds: {}(s) with {} characters"
                         .format(format(self.encrypt_time_for_algorithm, ".12f"), "{:,}".format(len(self.plaintext))))
        else:
            lines.append("Encrypted in these seconds: {}(s) with {} characters"
                         .format(format(self.encrypt_time_for_algorithm, ".12f")[0:14],
                                 "{:,}".format(len(self.plaintext)),
                                 "{:,}".format(self.num_blocks)))
            lines.append(" " * 55 + "and {} blocks ({} characters each)"
                         .format("{:,}".format(self.num_blocks),
                                 "{:,}".format(round(len(self.plaintext) / self.num_blocks, 2))))


        # Figure out the microseconds per character
        lines.append("Microseconds per character: {}(µs)"
                     .format(format(self.encrypt_time_for_algorithm / len(self.plaintext)* 1000000, ".12f")[0:14]) )

        # Print out spaces between the encryption stats and the decryption stats
        lines.append(" ")
        lines.append(" ")






        # Print out "DECRYPTION"
        lines.append("𝐃𝐄𝐂𝐑𝐘𝐏𝐓𝐈𝐎𝐍")


        # Print out the symmetric key again or the private key
        if self.DEFAULT_BLOCK_SIZE == 0:                                           # If not a block cipher
            lines.append("―――――――― key ――――――――")
            lines.append("{}".format(self.key))
            lines.append("―" * 67)

        elif self.DEFAULT_BLOCK_SIZE != 0 and self.CIPHER_TYPE == "symmetric":    # Is a symmetric block cipher
            lines.append("―" * 67)
            lines.append("―――――――― {}-bit key ".format(self.key_size).ljust(73, "―"))
            lines.append("{}".format(self.key))
            lines.append(("――――――――"
                          + " {}(s) ".format(format(self.encrypt_time_for_key, ".20f")[0:len(str(self.key_size)) + 5]))
                            .ljust(73, "―"))
            lines.append("―" * 67)

        # Print out the private key if is an asymmetric cipher
        if self.DEFAULT_BLOCK_SIZE != 0 and self.CIPHER_TYPE == "asymmetric":     # Is an asymmetric block cipher
            lines.append("―" * 67)
            lines.append("―――――――― {}-bit private key ".format(self.key_size).ljust(73 + 3, "―"))
            lines.append("{}".format(self.public_key))
            lines.append(("――――――――"
                          + " {}(s) ".format(format(self.encrypt_time_for_key,
                                                    ".20f")[0:len(str(self.key_size)) + 13]))
                            .ljust(73 + 3, "―"))
            lines.append("―" * 67)


        # Print out the encoding scheme/alphabet
        lines.append("The plaintext's alphabet is: \"{}\""
                     .format(get_char_set(self.original_plaintext, "alphabet")))

        # Print out the times longer than encryption
        lines.append("Times longer then encryption: {}(X)"
                     .format(format((self.decrypt_time_for_algorithm / self.encrypt_time_for_algorithm), ".2f")))


        # Print out the decryption time with characters (and blocks and characters per blocks if available)
        if self.CHAR_SET == "alphabet":
            lines.append("Decrypted in these seconds: {}(s) with {} characters"
                         .format(format(self.decrypt_time_for_algorithm, ".12f")[0:14],
                                 "{:,}".format(len(self.plaintext))))
        else:
            lines.append("Encrypted in these seconds: {}(s) with {} characters"
                         .format(format(self.decrypt_time_for_algorithm, ".12f")[0:14],
                                 "{:,}".format(len(self.plaintext)),
                                 "{:,}".format(self.num_blocks)))
            lines.append(" " * 55 + "and {} blocks ({} characters each)"
                         .format("{:,}".format(self.num_blocks),
                                 "{:,}".format(round(len(self.plaintext) / self.num_blocks, 2))))

        # Figure out the microseconds per character
        lines.append("Microseconds per character: {}(µs)"
                     .format(format(self.decrypt_time_for_algorithm / len(self.plaintext)* 1000000, ".12f")[0:14]) )



        # Add the extra lines for the individual cipher
        line_nums_to_insert = sorted(extra_lines.keys())          # First, get sorted list of the line numbers
        for line_num in line_nums_to_insert:                      # Insert line by line
            lines.insert(line_num, extra_lines.get(line_num))



        # Format everything after the third line (index 2)
        lines = lines[0:3] + format_to_colon(lines[3:])



        # Print out three spaces between the decryption stats and the rest of the text. Print first 100,000 chars
        lines.append(" ")
        lines.append(" ")
        lines.append("Ciphertext: ")
        length = len(self.ciphertext)
        if len(self.ciphertext) > 100000:
            lines.append(self.ciphertext[0:100000] + ".....To be continued.....")
        else:
            lines.append(self.ciphertext)

        lines.append(" ")
        lines.append(" ")
        lines.append("Decrypted text: ")
        if len(self.plaintext) > 100000:
            lines.append(self.plaintext[0:100000] + ".....To be continued.....")
        else:
            lines.append(self.plaintext)


        lines.append(" ")
        lines.append(" ")
        lines.append("Plaintext text: ")
        if len(self.original_plaintext) > 100000:
            lines.append(self.original_plaintext[0:100000] + ".....To be continued.....")
        else:
            lines.append(self.original_plaintext)







        # Concatenate all the strings, with a new line character between them. Then, write to file
        all_lines = "\n".join(lines)
        stats_file.write(all_lines)
        stats_file.close()







