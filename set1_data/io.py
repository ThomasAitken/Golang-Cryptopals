#This commented-out code was not used to provide me any data for the exercises, as I did not end up using the 'char_frequencies.txt' data, as this data did not distinguish upper and lower-case character frequencies.

# import re
# frequencies_dict = {}
# with open('char_frequencies.txt', 'r') as basic_file:
#     for line in basic_file.readlines():
#         frequencies_dict[line[0]] = float(re.search(r'\s\((.*)\%', line).group(1))

# print(frequencies_dict)

#Now, I know you are wondering: Why did I choose to use Portrait of the Artist as a Young Man by James Joyce as my source for English-language ASCII-character frequencies? It's objectively a bad choice for that purpose, if you were being serious about it, because Joyce has very abnormal punctuation. There is no good reason; I like the book. This said, I did do a tiny bit of 'find' and 'replace' work on non-Ascii punctuation in the plaintext I downloaded from Gutenberg, plus replaced '_' with '"' (in-paragraph quotations formatted bizarrely using _ blah blah _). Also, for these tasks, the statistical problem isn't complicated enough that the punctuation frequencies matter.

frequencies_dict = {}
total_chars = 0
bookstart = False
bookend = False
with open('portrait_of_artist.txt', 'r') as input_file:
    for line in input_file.readlines():
        if "*** START OF THIS PROJECT GUTENBERG EBOOK" in line:
            bookstart = True
            continue
        if "*** END OF THIS PROJECT GUTENBERG EBOOK PORTRAIT" in line:
            bookend = True
            continue
        if bookstart and not bookend:
            if line == "\n":
                continue
            elif line[0] == "-":
                continue
            else:
                for i in range(len(line)):
                    if line[i] != "\n":
                        total_chars += 1
                        if line[i] not in frequencies_dict:
                            frequencies_dict[line[i]] = 1
                        else:
                            frequencies_dict[line[i]] += 1

print(frequencies_dict)
print(total_chars)

#frequencies_dict was turned into the below by manual pruning of keys I didn't want from output... Code is only the best way of doing things 99% of the time.
cleaned_output = {'P': 99, 'r': 17883, 'o': 23171, 'd': 15435, 'u': 8170, 'c': 6975, 'e': 40215, ' ': 68637, 'b': 4432, 'y': 5628, 'C': 304, 'l': 14133, 'h': 21839, 'a': 25040, 't': 27282, '.': 3727, 'H': 900, 'T': 982, 'M': 284, 'L': 140, 'v': 2505, 's': 20508, 'i': 20851, 'n': 22099, 'A': 590, 'F': 183, 'w': 7187, 'f': 8327, 'Y': 91, 'g': 6617, 'J': 70, 'm': 7257, 'p': 5073, 'I': 637, 'V': 40, '"': 252, 'E': 109, 'O': 179, ',': 3140, '1': 18, '8': 2, 'k': 2639, ':': 534, 'B': 299, 'W': 271, 'q': 291, 'S': 517, '\'': 519, 'U': 22, 'D': 248, 'R': 64, 'K': 26, 'N': 110, '-': 180, 'x': 255, '!': 190, 'z': 110, 'j': 246, ';': 181, '?': 317, 'G': 275, 'Q': 9, '(': 3, ')': 3, '2': 12, '9': 3, 'Ã': 6, 'Z': 2, 'X': 8, 'Å': 2, '3': 5, '0': 4, '4': 4, '5': 3, '6': 4, '7': 1}

total_chars = sum(count for count in cleaned_output.values())
frequencies = {}
for key,value in cleaned_output.items():
    frequencies[key] = round(100*value/total_chars, 2)
print(frequencies)
