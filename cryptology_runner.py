
import datetime # to be used in fileName






#  Print out available Encryption/Decryption types
def usage():
    print("Encryption/Decryption types available: ")
    print(*both_list, sep=', ')
    print(*decryption_only_list, sep='(Decryption only), ')


encryption_list = ["vigenere", "vigenere_multiplicative", "vigenere_exponential", "rotation"]
decryption_list = ["vigenere", "vigenere_multiplicative", "vigenere_exponential", "rotation", "rotation_unknown"]


#  construct a list containing cipher method in both encryption AND decryption
both_list = []
decryption_only_list = []
for x in range(0, len(decryption_list)):
    if decryption_list[x] in encryption_list:
        both_list.append(decryption_list[x])
    else:
        decryption_only_list.append(decryption_list[x])




#  IMPORTANT VARIABLES
cipher = "" #  This stores the cipher type that the user wants to use
encrypt = None #  This decides whether encryption or decryption is used

data = "" #  This is the info to be processed

file_given = None # stores whether or not a file was given
output_location = "" # the output location of the generated file
output = ""






#  Print out info when the program first begins
print()
print("See README for usage."
        + "\nTo print out the available cipher types, type \"help\".")
print()
usage()










# error message booleans
previous_statement_invalid = False
no_args_supplied = False
no_file_given = False
invalid_file = False
string_format_invalid = False
no_cipher_given = False
no_command_given = False
invalid_cipher = False
empty_input = False


#  FOREVER LOOP THAT CONTINUALLY TAKES USER INPUT
while(True):



    # Refresh important variables for the next command
    cipher = ""  # This stores the cipher type that the user wants to use
    encrypt = None  # This decides whether encryption or decryption is used

    data = ""  # This is the info to be processed

    file_given = None  # stores whether or not a file was given
    output_location = ""  # the output location of the generated file
    output = ""




    #  Default no error message
    if not previous_statement_invalid:
        print()
        print()
        print()
        statement = input("Enter statement: ")

    #  Run when there was an error with the previous message
    else:
        print()
        print()
        print()
        if no_args_supplied:
            statement = input("No arguments are supplied! Try again: ")
            no_args_supplied = False
        elif no_file_given:
            statement = input("No file given! Try again: ")
            no_file_given = False
        elif invalid_file:
            statement = input("No such file or directory! Try again: ")
            invalid_file = False
        elif string_format_invalid:
            statement = input("The string was impromperly formatted! Try again: ")
            string_format_invalid = False
        elif no_cipher_given:
            statement = input("No cipher given! Try again: ")
            no_cipher_given = False
        elif no_command_given:
            statement = input("No command given! Try again: ")
            no_command_given = False
        elif invalid_cipher:
            statement = input("Cipher was invalid! Try again: ")
            invalid_cipher = False
        elif empty_input:
            statement = input("There is no data to process! Try again: ")
            empty_input = False
        else:
            statement = input("Statement invalid! First flag unrecognized. Try again: ")


        previous_statement_invalid = False




    #  split the statement into an array of words
    commands = statement.split()

    # if there is no input, return an error
    if len(statement) == 0:
        previous_statement_invalid = True
        no_command_given = True
        continue

    #  process the first word in the statement
    if commands[0] == "help":
        usage()
        continue

    elif commands[0] == "exit":
        break

    elif commands[0] == "-e":
        encrypt = True
        #  check if there are arguments following -e and make note of it if there are none
        if len(commands) == 1:
            previous_statement_invalid = True
            no_args_supplied = True
            continue

    elif commands[0] == "-d":
        encrypt = False
        #  check if there are arguments following -d and make note of it if there are none
        if len(commands) == 1:
            previous_statement_invalid = True
            no_args_supplied = True
            continue

    else:
        previous_statement_invalid = True
        continue






    index = 1 #  This is the current index for the array statement

    #  PROCESS THE INPUT TEXT/FILE (second part) in the statement. Test if a string is entered(with quotation marks)
    if commands[index][0] == "\"":

        # update file_given
        file_given = False

        try:
            data = statement[statement.index("\"") + 1: statement.rindex("\"")]
        except ValueError:
            previous_statement_invalid = True
            string_format_invalid = True
            continue

        # update index(it should be the last one containing a quotation mark plus 1)
        for i in range(len(commands) - 1, 0, -1):
            if "\"" in commands[i]:
                index = i + 1
                break


    #  Otherwise, a file is given
    else:

        # update file_given
        file_given = True

        #  open the file and store its contents in the string data
        try:
            my_file = open(commands[index], "r", encoding="utf-8")
            data = my_file.read()
            my_file.close()
        except IOError:
            previous_statement_invalid = True
            invalid_file = True
            continue

        # update index
        index = index + 1


    #  if the input was empty, return an error
    if len(data) == 0:
        empty_input = True
        previous_statement_invalid = True
        continue
    # END OF PROCESSING DATA INPUT








    # PROCESS THE NEXT PART OF THE STATEMENT(THE CIPHER) CHECK FOR NO ARGUMENTS FIRST
    if index >= len(commands):
        previous_statement_invalid = True
        no_cipher_given = True
        continue
    #  otherwise an argument is given
    else:
        given_cipher = commands[index]

        #  make sure that the given cipher is a valid type for encryption
        if encrypt:
            for x in range(0, len(encryption_list)):
                if given_cipher == encryption_list[x]:
                    cipher = given_cipher
                    break
        #  if in decryption mode, make sure a valid decryption cipher is chosen
        else:
            for x in range(0, len(decryption_list)):
                if given_cipher == decryption_list[x]:
                    cipher = given_cipher
                    break

        #  if there is no valid cipher, return error
        if cipher == "":
            previous_statement_invalid = True
            invalid_cipher = True
            continue
    #  update the index for parsing through commands
    index = index + 1
    # END OF PROCESSING CIPHER






    # FIGURE OUT THE LOCATION FOR THE NEW GENERATED FILE. CREATE A DEFAULT LOCATION FIRST
    now = datetime.datetime.now()
    if encrypt:
        #  if file given, use the original name of the file as part of the new name, otherwise end it in encrypted.txt
        if file_given:
            try:
                output_location = "Encrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_" + cipher + "_encrypted_" + \
                                   commands[1][commands[1].rindex("/") + 1:]
            except ValueError:
                output_location = "Encrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_" + cipher + "_encrypted_" + \
                                   commands[1]
        else:
            output_location = "Encrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_" + cipher + "_encrypted"

    # else decrypt
    else:
        #  if file given, use the original name of the file as part of the new name, otherwise end it in decrypted.txt
        if file_given:
            try:
                output_location = "Decrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_DECRYPTED_" + \
                                  commands[1][commands[1].rindex("/") + 1:]
            except ValueError:
                output_location = "Decrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_DECRYPTED_" + \
                                  commands[1]
        else:
            output_location = "Decrypted/" + now.strftime("%Y-%m-%d_h%Hm%Ms%S") + "_DECRYPTED"

    # take input for the location of the output(if there is one)
    if index < len(commands):
        output_location = commands[index]


    #  print out the data, and let the user know where the output location is
    print("\nTHIS IS THE DATA: \n" + data)
    print(("*******************************************************"))
    print("\nNEW FILE LOCATED HERE: " + output_location)
    print("TYPE \"info\" FOR MORE INFORMATION ON FURTHER PROMPTS.\n")
    # END OF CREATING OUTPUT LOCATION







    #  EXECUTE THE ENCRYPTION/DECRYPTION ON THE DATA, first import the proper module, then use encrypt/decrypt
    if encrypt:
        exec("from Cryptography import " + cipher)
        exec("output = " + cipher + ".encrypt(data, output_location)")
    else:
        exec("from Cryptanalysis import " + cipher)
        exec("output = " + cipher + ".decrypt(data, output_location)")

    print(("*******************************************************"))
    print("\nTHIS IS THE OUTPUT:\n" + output)




    #  WRITE TO THE PROPER FILE
    new_file = open(output_location, "w", encoding="utf-8")
    new_file.write(output)
    new_file.close()

#  END OF FOREVER LOOP



