import sys
#!/usr/bin/python3

import codecs
import base64


hex_string = sys.argv[1]

xor_string = sys.argv[2]

def hex_to_64(hex_string):
    # Convert string to hex
    hex1 = codecs.decode(hex_string, 'hex')
    # print(hex1)

    # Encode as base64 (bytes)
    codecs.encode(hex1, 'base64')


    # Standard Base64 Encoding
    encoded_bytes = base64.b64encode(hex1)
    encoded_str = str(encoded_bytes, "utf-8")

    return(encoded_str)

string_64 = hex_to_64(hex_string)



def xor_strings(s, t) -> str:
    """xor two strings together."""
    if isinstance(s, str):
        # Text strings contain single characters
        byte_string = b"".join(chr(ord(a) ^ ord(b)) for a, b in zip(s, t))
        encoded_bytes = base64.b64encode(byte_string)
        encoded_str = str(encoded_bytes, "utf-8")
        return encoded_str

    else:
        # Python 3 bytes objects contain integer values in the range 0-255
        return bytes([a ^ b for a, b in zip(s, t)])
print(string_64, xor_string)

xor_result = xor_strings(string_64, xor_string)
print(xor_result)



#or, if I had to do my own algorithm, it would work as follows:

#(i) determine digit length of hex-encoded string
#(ii) sum <-- 0
#(iii) while index is decreasing from (length(str)-1) to 0:
#       x <-- (16^index)*digit_value
#       sum <-- sum + x
#(iv) encoded_verdict <-- convert_to_64(sum)
#       

#So we require one simple function: convert_to_64(dec_x)