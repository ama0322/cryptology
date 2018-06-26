import miscellaneous # To handle user input and miscellaneous










# Encrypt using user-entered info. Write relevant information and return encrypted text for cryptography_runner
def execute(data, output_location):
    """
    This function calls the appropriate functions in miscellaneous.py. Those functions will use the encrypt() function
    located below as the algorithm to actually encrypt the text. Then, the cipher text will be returned back to
    cryptography_runner.py

    :param data: (string) the data to be encrypted
    :param output_location: (string) the location to print out the information
    :return: (string) the encrypted data
    """

    # Obtain the encrypted text. Also write statistics and relevant info a file
    encrypted = miscellaneous.encrypt_and_generate_asymmetric_keys(data, output_location, "Encryption", "rsa", "encrypt")



    # Return encrypted text to be written in cryptography_runner
    return encrypted







# The actual algorithm to encrypt using rsa encryption
def encrypt(plain_text):
    """
    This encrypts using an rsa encryption. Random primes for the key are generated.

    :param plain_text: (string) the data to be encrypted
    :return: (string) the encrypted text
    :return: (string) the generated public key for this in string form
    :return: (string) the generated private key for this in string form
    """


