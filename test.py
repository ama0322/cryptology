import cryptography_runner # for decryption_set
import time # for timing
import datetime # for labelling the date that files are created
import miscellaneous
import os # for deleting files




############################################################################################## MANUAL TESTING ##########

# MODIFY THESE VALUES
plaintext_source = "Library/Eleonora.txt"

char_set_size = miscellaneous.char_set_to_char_set_size.get("unicode_plane0")
key = "This is a key for testing"

char_scheme_size = miscellaneous.char_set_to_char_set_size.get("base4096")




# This function enters the testing mode where the user can enter commands to see check ciphers and see stats
def testing_mode():

        # Forever while loop to take in user commands and execute them
        while True:

                # Get the decryption type and the encryption type (same name as decyption but w/o "_nokey")
                decryption = _parse_user_input()
                encryption = decryption[0: decryption.find("_nokey")]

                # Obtain the plaintext
                my_file = open(plaintext_source, "r", encoding="utf-8")
                plaintext = my_file.read()
                my_file.close()

                # Create the output location for this run
                now = datetime.datetime.now()
                output_location = "Files_Logs/" + decryption + "_" + now.strftime("%Y-%m-%d_h%Hm%Ms%S")


                # Conduct test for symmetric ciphers
                if decryption in miscellaneous.symmetric_ciphers:

                    # Adjust the key for the encryption used (1st char for single character encryption like rotation)
                    if miscellaneous.encryption_key_type.get(encryption) == 1:
                        global key;
                        key = key[0]

                    # Encrypt the plaintext.
                    start_time = time.time()
                    exec("from Encryption import " + encryption)
                    ciphertext = eval(encryption + ".encrypt(plaintext, key, char_set_size)")
                    encryption_time = time.time() - start_time

                    # Figure out if the decryption method needs a key ("_nokey" doesn't need one)
                    needs_key = "_nokey" not in decryption

                    # Decrypt the plaintext. Call testing execute
                    exec("from Decryption import " + decryption)
                    exec(decryption + ".testing_execute(ciphertext, output_location, plaintext, key, "
                                      "                 char_set_size, encryption_time)")




                # Conduct test for asymmetric ciphers
                elif decryption in miscellaneous.asymmetric_ciphers:

                    # Encrypt the plaintext, and get the generated ciphers
                    start_time = time.time()
                    exec("from Encryption import " + encryption)
                    ciphertext, public_key, private_key = eval(encryption + ".encrypt(plaintext, \"\", "
                                                                          + "char_scheme_size)")
                    encryption_time = time.time() - start_time

                    # Decrypt the plaintext using the private key. Call testing execute
                    exec("from Decryption import " + decryption)
                    exec(decryption + ".testing_execute(ciphertext, output_location, plaintext, public_key, "
                                      + "private_key, char_scheme_size, encryption_time)")



# Obtain commands from the user
def _parse_user_input():
        """
        This prompts the user and reads user info. The user may choose to change the default ciphertext location by
        entering "set " followed by the file of the ciphertext. Otherwise, the user specifies a decryption method to
        test

        :return: (string) the decryption method to test
        """

        # Prompt the user for a command
        statement = input("Enter a testing mode command: ")

        # Loop until the user enters a legitimate decryption type
        while True:

                # split the statement into an array of words
                command = statement.split()

                # If empty, continue
                if statement == "":
                        statement = input("No command entered! Enter a testing mode command: ")
                        continue

                # Check if the user decides to clear logs
                if command[0] == "clear":
                        # delete files in /Files_Logs
                        for file in os.listdir("Files_Logs"):
                                os.unlink("Files_Logs/" + file)

                        statement = input("Logs cleared. Enter a testing mode command: ")
                        continue



                # Check that the command is a legitimate decryption type. If so, break out of loop
                if statement in miscellaneous.decryption_set:
                        break

                # Prompt the user for a command again
                statement = input("Invalid command! Enter a testing mode command: ")

        return statement













########################################################################################### AUTOMATED TESTING ##########