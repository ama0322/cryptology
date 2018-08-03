from abc import ABC, abstractmethod # To create abstract classes






class Cipher(ABC):




    # Constructor
    def __init__(self, plaintext:str, ciphertext:str, char_set:str, mode_of_operation:str, key:str, public_key:str,
                 private_key:str, block_size:int, key_size:int, source_location:str, output_location:str) -> None:
        super().__init__()

        # Variables that detail the manner in which the encryption/decryption is done. Not all must be set
        self.plaintext         = plaintext         # (str) The plaintext
        self.ciphertext        = ciphertext        # (str) The ciphertext
        self.char_set          = char_set          # (str) The name of the character set to use
        self.mode_of_operation = mode_of_operation # (str) The name of the mode of operation to use

        self.key               = key               # (str) For symmetric ciphers, the symmetric key
        self.public_key        = public_key        # (str) For asymmetric ciphers, the public key
        self.private_key       = private_key       # (str) For asymmetric ciphers, the private key

        self.block_size        = block_size        # (int) For block ciphers, the size of the block
        self.key_size          = key_size          # (int) For block ciphers, the size of the key

        self.source_location   = source_location   # (str) The filepath of the source of the plaintext/ciphertext
        self.output_location   = output_location   # (str) The filepath of the output file

        # Variables that hold information about the encryption/decryption. Set these during/after encryption/decryption
        self.processed_data    = ""                # (str)   The result of the encryption/decryption
        self.num_blocks        = 0                 # (int)   The number of blocks used during encryption/decryption
        self.time              = 0.0               # (float) The time it takes for encryption/decryption ONLY
        self.time_for_keys     = 0.0               # (float) The time it takes to handle keys (generate, schedule, ...)







    # The algorithm to encrypt plaintext
    @abstractmethod
    def encrypt_plaintext(self):
        pass


    # The algorithm to decrypt plaintext
    @abstractmethod
    def decrypt_ciphertext(self):
        pass