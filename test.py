import cryptography_runner # for decryption_set
import time # for timing
import datetime # for labelling the date that files are created
import miscellaneous



plain_text_source = "Library/Around_the_World_in_80_Days.txt"
char_set_size = 256


# This function enters the testing mode where the user can enter commands to see check ciphers and see stats
def testing_mode():

        # Forever while loop to take in user commands and execute them
        while True:

                # Get the decryption type and the encryption type
                decryption = _parse_user_input()
                encryption = miscellaneous.decryption_corresponding_encryption.get(decryption)

                # Obtain the plaintext
                my_file = open(plain_text_source, "r", encoding="utf-8")
                plain_text = my_file.read()
                my_file.close()

                # Create the output location for this run
                now = datetime.datetime.now()
                output_location = "Files_Logs/" + decryption + "_" + now.strftime("%Y-%m-%d_h%Hm%Ms%S")

                # Random key
                key = "Key for testing."

                # Adjust the key for the encryption used (1st char for single character encryption like rotation)
                if miscellaneous.encryption_key_type.get(encryption) == 1:
                        key = key[0]


                # Encrypt the plaintext.
                start_time = time.time()
                exec("from Encryption import " + encryption)
                cipher_text = eval(encryption + ".encrypt(plain_text, key, char_set_size)")
                encryption_time = time.time() - start_time


                # Figure out if the decryption method needs a key
                needs_key = miscellaneous.does_decryption_need_key.get(decryption)

                # Decrypt the plaintext. Call the right form of testing execute
                exec("from Decryption import " + decryption)
                if needs_key:
                        exec(decryption + ".testing_execute(cipher_text, output_location, plain_text, key, "
                                          "                 char_set_size, encryption_time)")
                else:
                        exec(decryption + ".testing_execute(cipher_text, output_location, plain_text, encryption_time)")





# Obtain commands from the user
def _parse_user_input():
        """
        This prompts the user and reads user info. The user may choose to change the default ciphertext location by
        entering "set " followed by the file of the ciphertext. Otherwise, the user specifies a decryption method to
        test

        :return: (string) the decryption method to test
        """

        # Prompt the user for a command
        statement = input("Enter a command: ")

        # Loop until the user enters a legitimate decryption type
        while True:

                # split the statement into an array of words
                command = statement.split()

                # Check if the user decides to set plaintext
                if command[0] == "set":

                        # If len(commands) < 2, insufficient arguments
                        if len(command) < 2:
                                statement = input("Insufficient arguments! Enter a command: ")
                                continue

                        # If len(commands) > 2, excessive arguments
                        if(len(command)):
                                continue

                        # Check that commands[1] is a legitimate plaintext source.
                        try:
                                my_file = open(command[1], "r", encoding="utf-8")
                                my_file.close()

                                global plain_text_source
                                plain_text_source = command[1]
                                statement = input("Plaintext source updated. Enter a command: ")
                        except IOError:
                                statement = input("No such file or directory! Enter a command: ")
                                continue


                # Check that the command is a legitimate decryption type. If so, break out of loop
                if statement in cryptography_runner.decryption_set:
                        break

                # Prompt the user for a command again
                statement = input("Invalid command! Try again: ")

        return statement

