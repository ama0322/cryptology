import time                 # To get access to current time
import threading            # To create threading for the ProgressBar












# Wraps around range-type objects to allow for access to the current iteration
class RangePlus:#region...
    """
    This class is a replacement for the range-type object returned by range(). This is done because I cannot access the
    current index that is iterating in the range-type object. As a result, this class is essentially the same as the
    range-type, except that it adds three main things.

    1. An int instance variable that keeps track of the iterating index
    2. A string instance variable named "prompt". As this will be used in the progress-bar, this variable "prompt"
       describes what this loop is doing.
    3. Multiple string class variables that serve as possible "prompts". Use these when creating RangePlus objects as
       the first parameter (see the docstring for __init__())
    """

    # Possible prompts used to describe the for-loop (All same length so progress-bars look nice)
    ENCRYPTING_CHARS = "Encrypting characters:    "
    DECRYPTING_CHARS = "Decrypting characters:    "
    ENCRYPTING_BLOCS = "Encrypting blocks:        "
    DECRYPTING_BLOCS = "Decrypting blocks:        "



    # Construct the object by wrapping an iterator around range(). ALSO, BEGINS THE PROGRESSBAR THREAD
    def __init__(self, *params):#region...
        """
        This takes in *params which are the same parameters for range()*. This initializer wraps an iter() around the
        object returned by range(), and allows for better access into the for-loop variables.

        *Actually, the first parameter is the string description of the process that is going on. The other parameters
        following this first parameter are exactly the same though.

        :param params[0]:   (string) The prompt that tells what the progress-bar is for
        :param params[>=1]: (int)    Same as range()'s parameters
        """
        self.range_iterator = iter(range(*params))
        self.current = None
        self.prompt = params[0]
        self.start = 0
        self.end = 0
        self.step = 1

        # If all three parameters given, fill them in
        if len(params) == 4:
            self.start = params[1]
            self.end = params[2]
            self.step = params[3]

        # If both start and end given, fill those in
        elif len(params) == 3:
            self.start = params[1]
            self.end = params[2]

        # Else, only end is given, so fill that in
        else:
            self.start = 0
            self.end = params[1]


        # Create the ProgressBar thread, and run it
        thread = ProgressBar(self)
        thread.start()


    #endregion


    # Called by "in"-operator. Returns the iterator (itself)
    def __iter__(self):#region...
        return self
    #endregion


    # Called by "in"-operator. Used in for-loops to advance to the next element in this range
    def __next__(self):#region...
        self.current = next(self.range_iterator)
        return self.current
    #endregion
#endregion




# This class contains everything to handle creating a progress bar
class ProgressBar(threading.Thread):#region...


    # This is the constructor for the loading object
    def __init__(self, range_plus):#region...
        """
        Creates the ProgressBar, and sets up important variables

        :param range_plus: (BarRange) The iterator that the for-loop uses
        """

        # Setup for variables
        self.range_plus = range_plus
        self.start_time = time.time()

        self.prompt     = range_plus.prompt

        self.start      = range_plus.start
        self.end        = range_plus.end
        self.step       = range_plus.step
        self.current    = range_plus.start

        # Call super-method
        super().__init__()
    #endregion


    # Called from RangePlus constructor. This runs the progress-bar
    def run(self):#region...
        """
        This function runs the progress-bar, printing in one line how far progress has gone.

        :return: None
        """

        # Important variables
        bar_length = 100
        progress_bar = "{}{}%|{}| {}/{} [Time elapsed:{}, Time estimated:{}, {} {}/sec]"


        # Print out for the first time (No iterations taken place yet)
        print ("\r" + progress_bar
               .format(self.prompt, 0, "▏" * bar_length)),


        pass
    #endregion
#endregion





############################################################################################### MISCELLANEOUS ##########


# Same as ord(), but adjusted to avoid surrogates
cdef int ord_adjusted(str character):#region...
    """
    Because the regular ord doesn't adjust for surrogates, this one does.

    :param character: (str) The character to get the ord() of, adjusted for surrogates. MUST be a character
    :return:          (int) The adjusted ord() result
    """

    ord_result = ord(character)


    # Adjust the ord result
    if ord_result >= 57343:   # 55296 is the UPPER INCLUSIVE bound of the surrogates
        ord_result -= 2048    # 2048 is the number of surrogate characters

    return ord_result
# endregion

# Same as chr(), but adjusted to avoid surrogates
cdef str chr_adjusted(int unicode_val):#region...
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





















































