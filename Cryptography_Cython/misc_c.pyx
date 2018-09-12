import time # To get access to current time




















############################################################################################### MISCELLANEOUS ##########


# Same as ord(), but adjusted to avoid surrogates
cpdef int ord_adjusted(str character):#region...
    """
    Because the regular ord doesn't adjust for surrogates, this one does.

    :param character: (str) The character to get the ord() of, adjusted for surrogates. MUST be a character
    :return:          (int) The adjusted ord() result
    """

    ord_result = ord(character)


    # Adjust the ord result
    if ord_result >= 57343:               # 55296 is the UPPER INCLUSIVE bound of the surrogates
        ord_result -= 2048    # 2048 is the number of surrogate characters

    return ord_result
# endregion

# Same as chr(), but adjusted to avoid surrogates
cpdef str chr_adjusted(int unicode_val):#region...
    """
    Same as chr() but adjusts to skip surrogates

    :param unicode_val: (int) the unicode value to get the char of
    :return:            (str) the character to return
    """

    # Adjust the unicode value if necessary
    if unicode_val >= 55296:   # 55296 is the LOWER INCLUSIVE bound of the surrogates
        unicode_val += 2048    # 2048 is the number of surrogate characters

    return chr(unicode_val)
#endregion







# Print updates at some interval
cdef double print_updates_TimeInterval  = 0.01
cdef double print_updates_TimeLastPrint = 0
cdef int print_updates_CharsTotalLen = 0
cpdef void print_updates(str prompt, int chars_finished, int chars_total):#region...
    """
    This function prints the percentage of the operation that calls this that is done. 
    
    :param prompt:         (str)  The prompt to print out before the percentage
    :param chars_finished: (int)  The number of characters that are finished
    :param chars_total:    (int)  The number of characters that need to be processed
    :return:               (None)
    """

    # Load all the "static variables"
    global print_updates_TimeInterval
    global print_updates_TimeLastPrint
    global print_updates_CharsTotalLen


    # Store the percent_done here (when printing after an interval)
    cdef double percent_done

    # Print if first character
    if chars_finished == 1:

        # Set the static var for chars_total_len
        print_updates_CharsTotalLen = len("{:,}".format(chars_total))

        # Print and update the time
        print_updates_TimeLastPrint = time.time()
        print ("\r{}\t\t\tPercent of text done: {}{}%{} \t\t\t\twith {} characters"
               .format(prompt,
                      "\u001b[32m",
                      "0.00".rjust(6, " "),
                      "\u001b[0m",
                      "{:,}".format(chars_finished).rjust(print_updates_CharsTotalLen, " "))),
        return

    # Print if an interval has passed
    elif time.time() - print_updates_TimeLastPrint >= print_updates_TimeInterval:

        # Print and update the time
        print_updates_TimeLastPrint = time.time()                               # Get current time
        percent_done = (<double> chars_finished / <double> chars_total) * 100   # Calculate percent done
        print ("\r{}\t\t\tPercent of text done: {}{}%{} \t\t\t\twith {} characters"
               .format(prompt,
                      "\u001b[32m",
                      format(percent_done, ".2f").rjust(6, " "),
                      "\u001b[0m",
                      "{:,}".format(chars_finished).rjust(print_updates_CharsTotalLen, " "))),
        return

    # Print if on last character. This line not to be overwritten, unlike the above two cases
    elif chars_finished == chars_total:

       # Set static vars back to 0 (aside from the interval) for the next encryption/decryption
        print_updates_TimeLastPrint = 0
        print_updates_CharsTotalLen = 0

        print ("\r{}\t\t\tPercent of text done: {}{}%{} \t\t\t\twith {} characters"
               .format(prompt,
                      "\u001b[32m",
                      "100.00".rjust(6, " "),
                      "\u001b[0m",
                      "{:,}".format(chars_finished).rjust(print_updates_CharsTotalLen, " ")))
        return
#endregion





















































