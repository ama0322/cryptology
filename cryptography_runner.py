import datetime # to be used in fileName
import os # to delete files in decrypted and encrypted
import test # to run testingmode







# Sets containing available options for encryption/decryption. Add to this.
encryption_set = {"vigenere", "vigenere_multiplicative",
                  "vigenere_exponential", "rotation"}

decryption_set = {"vigenere", "vigenere_multiplicative",
                  "vigenere_exponential", "rotation", "rotation_unknown"}

both_set = encryption_set & decryption_set # the set containing options in both encryption_list and decryption_list
decryption_only_set = decryption_set - encryption_set # the set containing options only in decryption_list

last = "" # Store the path to the last created encrypted file



###################################################################################### START OF MAIN FUNCTION ##########
def main():


    #  Print out info when the program first begins
    print()
    print("See README for usage."
           + "\nTo print out the available cipher types, type \"help\".")
    print()
    usage()


    # forever while loop to continually take in user input and executing commands
    while True:

        # Obtain information from the user command
        cipher, encrypt, data, output_location = parse_user_input()

        # Set up the global variable last for next iteration
        global last
        last = output_location

        # print out the data, and let the user know where the output location is
        print_data_and_location( data, output_location )

        # execute the encryption/decryption on the data
        execute_encryption_or_decryption( encrypt, cipher, data, output_location )

    # End of forever while loop
######################################################################################## END OF MAIN FUNCTION ##########


# Print out available Encryption/Decryption types
def usage():
    print("Encryption/Decryption types available: ")
    print(*both_set, sep=', ')
    print(*decryption_only_set, sep='(Decryption only), ')


# Parse user input and return relevant information
def parse_user_input():
    """
    This function parses user input and returns relevant information

    :return: cipher - (string) stroes the cipher type that the user wants to use
    :return: encrypt - (boolean) decides whether encryption or decryption is used
    :return: data - (string) the information to be encrypted/decrypted
    :return: output_location - (string) the output location of the generated file
    """




    statement = input("Enter statement: ") # obtain user input

    # While the statement is invalid, keep prompting the user. If valid, break from loop
    while True:


        commands = statement.split() #  split the statement into an array of words


        # if no input, prompt the user to enter a statement
        if len(statement) == 0:
            statement = input("No arguments are supplied! Try again: ")
            continue




        # PROCESS THE FIRST WORD IN THE STATEMENT
        # If command is "help", print usage, and ask for another statement
        if commands[0] == "help":
            usage()
            statement = input("Enter statement: ")  # obtain user input
            continue

        # If command is "exit", then exit
        elif commands[0] == "exit":
            exit()

        # If command is "test", then enter testing mode
        elif commands[0] == "test":
            test.testing_mode()

        # If command is "-e", then set encrypt and check for the following argument
        elif commands[0] == "-e":
            encrypt = True
            #  check if there are arguments following -e and make note of it if there are none
            if len(commands) == 1:
                statement = input("No arguments are supplied! Try again: ")
                continue

        elif commands[0] == "-d":
            encrypt = False
            #  check if there are arguments following -d and make note of it if there are none
            if len(commands) == 1:
                statement = input("No arguments are supplied! Try again: ")
                continue

        elif commands[0] == "clear":
            # delete files in /Files_Decrypted
            for file in os.listdir("Files_Decrypted"):
                    os.unlink("Files_Decrypted/" + file)
            # delete files in /Files_Encrypted
            for file in os.listdir("Files_Encrypted"):
                    os.unlink("Files_Encrypted/" + file)

            # Obtain next command
            statement = input("Enter statement: ")  # obtain user input
            continue

        else:
            statement = input("Unrecognized command! Try again: ")
            continue








        # PROCESS THE INPUT TEXT/FILE (second part) in the statement.
        index = 1  # This is the current index for the array statement
        if commands[index] == "last":

            file_given = True # update file_given

            #  open the file and store its contents in the string data
            try:
                my_file = open(last, "r", encoding="utf-8")
                data = my_file.read()
                my_file.close()
            except IOError:
                statement = input("There is no last file! Try again: ")
                continue

            # update index
            index = index + 1

        elif commands[index][0] == "\"": # Test if a string is entered(with quotation marks)

            file_given = False # update file_given

            # Try to read the string data
            try:
                data = statement[statement.index("\"") + 1: statement.rindex("\"")]
            except ValueError:
                statement = input("The string was impromperly formatted! Try again: ")
                continue

            # update index(it should be the last one containing a quotation mark plus 1)
            for i in range(len(commands) - 1, 0, -1):
                if "\"" in commands[i]:
                    index = i + 1
                    break


        # Otherwise, a file is given
        else:

            file_given = True # update file_given

            #  open the file and store its contents in the string data
            try:
                my_file = open(commands[index], "r", encoding="utf-8")
                data = my_file.read()
                my_file.close()
            except IOError:
                statement = input("No such file or directory! Try again: ")
                continue

            # update index
            index = index + 1

        # if the input was empty, return an error
        if len(data) == 0:
            statement = input("There is no data to process! Try again: ")
            continue
            # END OF PROCESSING DATA INPUT



        # PROCESS THE NEXT PART OF THE STATEMENT(THE CIPHER) CHECK FOR NO ARGUMENTS FIRST
        cipher = "" # create variable to hold cipher (Nothing by default)
        if index >= len(commands):
            statement = input("No cipher given! Try again: ")
            continue
        # otherwise an argument is given
        else:
            given_cipher = commands[index]

            #  make sure that the given cipher is a valid type for encryption
            if encrypt:
                if given_cipher in encryption_set:
                        cipher = given_cipher

            # if in decryption mode, make sure a valid decryption cipher is chosen
            else:
                if given_cipher in decryption_set:
                        cipher = given_cipher

            # if there is no valid cipher, return error
            if cipher == "":
                statement = input("Cipher was invalid! Try again: ")
                continue

        index = index + 1 # update the index for parsing through commands
        # END OF PROCESSING CIPHER





        # FIGURE OUT THE LOCATION FOR THE NEW GENERATED FILE. CREATE A DEFAULT LOCATION FIRST
        now = datetime.datetime.now()
        if encrypt:
            #  if file given, use the original name of the file as part of the new name, otherwise end it in
            # encrypted.txt
            if file_given:
                try:
                    output_location = "Files_Encrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_" + cipher + \
                                      "_encrypted_" + \
                                      commands[1][commands[1].rindex("/") + 1:]
                except ValueError:
                    output_location = "Files_Encrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_" + cipher + \
                                      "_encrypted_" + \
                                      commands[1]
            else:
                output_location = "Files_Encrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_" + cipher + "_encrypted"

        # else decrypt
        else:
            #  if file given, use the original name of the file as part of the new name, otherwise end it in
            # decrypted.txt
            if file_given:
                try:
                    output_location = "Files_Decrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_DECRYPTED_" + \
                                      commands[1][commands[1].rindex("/") + 1:]
                except ValueError:
                    output_location = "Files_Decrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_DECRYPTED_" + \
                                      commands[1]
            else:
                output_location = "Files_Decrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_DECRYPTED"

        # take input for the location of the output(if there is one)
        if index < len(commands):
            output_location = commands[index]


        break # break out of forever while loop because everything ran fine

    # End of while loop to take user command

    return cipher, encrypt, data, output_location


# Print data and the output location
def print_data_and_location(data, output_location):

    print("\nTHIS IS THE DATA: \n" + data)
    print("*******************************************************")
    print("\nNEW FILE LOCATED HERE: " + output_location)
    print("TYPE \"info\" FOR MORE INFORMATION ON FURTHER PROMPTS.\n")


# execute encryption/decryption on the data, save the output, and print out the output
def execute_encryption_or_decryption( encrypt, cipher, data, output_location ):


    if encrypt:
        exec("from Encryption import " + cipher)
        output = eval(cipher + ".encrypt(data, output_location)")
    else:
        exec("from Decryption import " + cipher)
        output = eval(cipher + ".decrypt(data, output_location)")

    print("*******************************************************")
    print("\nTHIS IS THE OUTPUT:\n" + output)

    #  WRITE THE ENCRYPTED/DECRYPTED TEXT TO THE PROPER FILE
    new_file = open(output_location, "w", encoding="utf-8")
    new_file.write(output)
    new_file.close()







# Call the main function
if __name__ == "__main__":
    main()