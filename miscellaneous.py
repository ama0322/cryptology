import time # for timing the encryption/decryption processes


char_sets = ["unicode", "ascii", "extended_ascii"] #  unicode has max val of 1114111,
                                                   #  ascii has max val of 127
                                                   #  extended_ascii has max val of 255


char_set_to_num_chars = {
    "ascii": 128,
    "extended_ascii": 256,
    "unicode": 1114112
}




#  This function asks the user for a character set. It will only accept character sets that are available.
def take_char_set(char_sets):
    """
    This functions asks the user to input a selection(a char set). THis selection is compared against char_sets
    in order to make sure that it is a valid selection

    :param char_sets: the list of all character sets
    :return: (string) the selection
    :return: (integer) the number of characters in the selected character set
    """


    previous_entry_invalid = False
    #  TAKE AN INPUT FOR THE CHARACTER SET
    while True:

        #  Print out the prompt for the user. If the previous entry was invalid, say so
        if not previous_entry_invalid:
            selection = input("Enter the character set to be used: ")
        else:
            selection = input("Character set invalid! Enter a new character set: ")
            previous_entry_invalid = False

        # Print out the available character sets, then continue
        if selection[0:4] == "info":
            print("The available character sets are: ")
            for x in range(0, len(char_sets)):
                print("                                  " + char_sets[x])
            continue

        # Test that the user entry is a valid character set. If so, exit out of the forever loop
        for x in range(0, len(char_sets)):
            broken = False
            if selection.rstrip() == char_sets[x]:
                broken = True
                break
        if broken:
            break

        # If here, that means the entry was invalid. Loop again
        previous_entry_invalid = True
    # END OF FOREVER LOOP TO TAKE A CHARACTER SET



    # figure out the end_char of the character set
    end_char = char_set_to_num_chars.get(selection)



    return selection, end_char



# This function obtain a single char key from the user and returns that
def get_single_char_key():

    # TAKE A KEY
    key = input("Enter a key (single character only): ")

    # IF THE USER DID NOT GIVE ANYTHING, SEND AN ERROR MESSAGE AND FORCE THE USER TO ENTER IT AGAN
    while key == "":
        key = input("No key given! Enter a key (single character only): ")

    # IF THE USER DID NOT GIVE A SINGLE CHARACTER, FORCE THE USER TO ENTER IT AGAN
    while not len(key) == 1:
        key = input("Not a single character! Enter a key (single character only): ")

    return key



# This function obtain a general key from the user and returns that
def get_key():

    # TAKE A KEY
    key = input("Enter a key: ")

    # IF THE USER DID NOT GIVE ANYTHING, SEND AN ERROR MESSAGE AND FORCE THE USER TO ENTER IT AGAN
    while key == "":
        key = input("No key given! Enter a key (single character only): ")

    return key



# This function executes the specified encryption/decryption type and writes to a file encryption/decryption stats
def execute_and_write_info(data, key, char_set, output_location, package, module, encrypt_decrypt):
    """
    This function executes the specified
    :param data:
    :param key:
    :param char_set:
    :param output_location:
    :param package:
    :param module:
    :return:
    """

    # START THE TIMER
    start_time = time.time()

    # Obtain num_chars to use in the encryption method
    num_chars = char_set_to_num_chars.get(char_set)

    # EXECUTE THE ENCRYPTION/DECRYPTION METHOD
    exec("from " + package + " import " + module)
    encrypted = eval(module + "." + encrypt_decrypt + "(data, key, num_chars)")

    #  END THE TIMER
    elapsed_time = time.time() - start_time


    #  WRITE TO A NEW FILE CONTAINING RELEVANT INFO
    new_file = open(output_location + "_(Relevant information)", "w", encoding="utf-8")
    new_file.writelines(["The character set is : " + char_set,
                         "\nThe key is: " + key,
                         "\n Encoded/decoded in: " + str(elapsed_time) + " seconds.",
                         "\n That is " + str((elapsed_time/len(encrypted) * 1000000)) + " microseconds per character."])

    return encrypted

























