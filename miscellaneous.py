char_sets = ["unicode", "ascii", "extended_ascii"] #  unicode has max val of 1114111,
                                                   #  ascii has max val of 127
                                                   #  extended_ascii has max val of 255


char_set_to_end_char = {
    "ascii": 127,
    "extended_ascii": 255,
    "unicode": 1114111
}




#  This function asks the user for a character set. It will only accept character sets that are available.
def take_char_set(char_sets):
    """
    This functions asks the user to input a selection(a char set). THis selection is compared against char_sets
    in order to make sure that it is a valid selection

    :param char_sets: the list of all character sets
    :return: (string) the selection
    :return: (integer) the integer form of the last character of the character set
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
    end_char = char_set_to_end_char.get(selection)




    return selection, end_char
#  END OF DEF TAKE_CHAR_SET




























