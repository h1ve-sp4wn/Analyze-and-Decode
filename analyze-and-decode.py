import re
import base64
import binascii
import codecs
import string
import urllib.parse

def detect_base64(code):
    """
    Detects base64 encoded strings in JavaScript or Python code
    """
    base64_pattern = re.compile(r'([A-Za-z0-9+/=]{20,})')
    return re.findall(base64_pattern, code)

def decode_base64(encoded_strings):
    decoded_strings = []
    for encoded in encoded_strings:
        try:
            decoded = base64.b64decode(encoded).decode('utf-8')
            decoded_strings.append(decoded)
        except Exception as e:
            print(f"Base64 Decoding Error: {e}")
            continue
    return decoded_strings

def detect_hex(code):
    """
    Detects hexadecimal encoded strings.
    """
    hex_pattern = re.compile(r'\b([0-9A-Fa-f]{2})+\b')
    return re.findall(hex_pattern, code)

def decode_hex(hex_strings):
    decoded_strings = []
    for hex_string in hex_strings:
        try:
            decoded = bytes.fromhex(hex_string).decode('utf-8')
            decoded_strings.append(decoded)
        except Exception as e:
            print(f"Hexadecimal Decoding Error: {e}")
            continue
    return decoded_strings

def decode_unicode_escape(code):
    """
    Decode unicode escape sequences in the form of \uXXXX.
    """
    try:
        decoded = codecs.decode(code, 'unicode_escape')
        return decoded
    except Exception as e:
        print(f"Unicode Decoding Error: {e}")
        return code

def detect_rot13(code):
    """
    Detects ROT13 encoded strings.
    """
    rot13_pattern = re.compile(r'[A-Za-z]{5,}')
    return re.findall(rot13_pattern, code)

def decode_rot13(encoded_strings):
    decoded_strings = []
    for encoded in encoded_strings:
        decoded = codecs.decode(encoded, 'rot_13')
        decoded_strings.append(decoded)
    return decoded_strings

def detect_xor(code):
    """
    Detects XOR encoded strings (basic heuristic).
    """
    xor_pattern = re.compile(r'[A-Za-z0-9]{4,}')
    return re.findall(xor_pattern, code)

def decode_xor(encoded_strings, key=0xAA):
    decoded_strings = []
    for encoded in encoded_strings:
        decoded = ''.join(chr(ord(c) ^ key) for c in encoded)
        decoded_strings.append(decoded)
    return decoded_strings

def detect_caesar_cipher(code):
    """
    Detects potential Caesar cipher encoded strings.
    """
    caesar_pattern = re.compile(r'[A-Za-z]{3,}')
    return re.findall(caesar_pattern, code)

def decode_caesar_cipher(encoded_strings, shift=3):
    decoded_strings = []
    for encoded in encoded_strings:
        decoded = ''.join(
            chr(((ord(c) - 97 - shift) % 26) + 97) if 'a' <= c <= 'z' else
            chr(((ord(c) - 65 - shift) % 26) + 65) if 'A' <= c <= 'Z' else c
            for c in encoded
        )
        decoded_strings.append(decoded)
    return decoded_strings

def detect_base32(code):
    """
    Detects base32 encoded strings.
    """
    base32_pattern = re.compile(r'([A-Za-z2-7]+=*)')
    return re.findall(base32_pattern, code)

def decode_base32(encoded_strings):
    decoded_strings = []
    for encoded in encoded_strings:
        try:
            decoded = base64.b32decode(encoded).decode('utf-8')
            decoded_strings.append(decoded)
        except Exception as e:
            print(f"Base32 Decoding Error: {e}")
            continue
    return decoded_strings

def decode_url(encoded_strings):
    decoded_strings = []
    for encoded in encoded_strings:
        try:
            decoded = urllib.parse.unquote(encoded)
            decoded_strings.append(decoded)
        except Exception as e:
            print(f"URL Decoding Error: {e}")
            continue
    return decoded_strings

def decode_ascii85(encoded_strings):
    decoded_strings = []
    for encoded in encoded_strings:
        try:
            decoded = binascii.a85decode(encoded).decode('utf-8')
            decoded_strings.append(decoded)
        except Exception as e:
            print(f"Ascii85 Decoding Error: {e}")
            continue
    return decoded_strings

def detect_brotli(code):
    """
    Detects Brotli compressed data.
    """
    brotli_pattern = re.compile(r'\x1f\x8b\x08')
    return re.findall(brotli_pattern, code)

def decode_brotli(encoded_strings):
    decoded_strings = []
    for encoded in encoded_strings:
        try:
            decoded = brotli.decompress(encoded)
            decoded_strings.append(decoded.decode('utf-8'))
        except Exception as e:
            print(f"Brotli Decoding Error: {e}")
            continue
    return decoded_strings

def decode_atbash(encoded_strings):
    decoded_strings = []
    for encoded in encoded_strings:
        decoded = ''.join(
            chr(219 - ord(c)) if 'a' <= c <= 'z' else
            chr(219 - ord(c)) if 'A' <= c <= 'Z' else c
            for c in encoded
        )
        decoded_strings.append(decoded)
    return decoded_strings

def decode_morse(encoded_strings):
    morse_code_dict = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
        '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
        '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
        '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9', '/': ' '
    }
    decoded_strings = []
    for encoded in encoded_strings:
        try:
            morse_code = encoded.split(' ')
            decoded = ''.join(morse_code_dict.get(code, '') for code in morse_code)
            decoded_strings.append(decoded)
        except Exception as e:
            print(f"Morse Decoding Error: {e}")
            continue
    return decoded_strings

def decode_base58(encoded_strings):
    base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    decoded_strings = []
    for encoded in encoded_strings:
        decoded = 0
        for i, char in enumerate(reversed(encoded)):
            decoded += base58_alphabet.index(char) * (58 ** i)
        decoded_strings.append(decoded.to_bytes((decoded.bit_length() + 7) // 8, 'big').decode())
    return decoded_strings

def detect_encodings(code):
    encoded_strings = {
        'base32': detect_base32(code),
        'url': re.findall(r'%[0-9A-Fa-f]{2}', code),
        'ascii85': re.findall(r'<~[A-Za-z0-9+/=]+~>', code),
        'brotli': detect_brotli(code),
        'atbash': re.findall(r'[A-Za-z]{5,}', code),  # Might be overinclusive
        'morse': re.findall(r'([.-/]+)', code),  # Basic Morse pattern
        'base58': re.findall(r'[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{5,}', code)
    }
    return encoded_strings

def analyze_and_decode(code):
    decoded_results = {
        'base64_decoded': [],
        'hex_decoded': [],
        'unicode_decoded': [],
        'rot13_decoded': [],
        'xor_decoded': [],
        'caesar_decoded': [],
        'base32_decoded': [],
        'url_decoded': [],
        'ascii85_decoded': [],
        'brotli_decoded': [],
        'atbash_decoded': [],
        'morse_decoded': [],
        'base58_decoded': []
    }

    base64_strings = detect_base64(code)
    decoded_results['base64_decoded'] = decode_base64(base64_strings)

    hex_strings = detect_hex(code)
    decoded_results['hex_decoded'] = decode_hex(hex_strings)

    unicode_strings = [decode_unicode_escape(code)]
    decoded_results['unicode_decoded'] = unicode_strings

    rot13_strings = detect_rot13(code)
    decoded_results['rot13_decoded'] = decode_rot13(rot13_strings)

    xor_strings = detect_xor(code)
    decoded_results['xor_decoded'] = decode_xor(xor_strings)

    caesar_strings = detect_caesar_cipher(code)
    decoded_results['caesar_decoded'] = decode_caesar_cipher(caesar_strings)

    base32_strings = detect_base32(code)
    decoded_results['base32_decoded'] = decode_base32(base32_strings)

    url_strings = detect_url(code)
    decoded_results['url_decoded'] = decode_url(url_strings)

    ascii85_strings = re.findall(r'<~[A-Za-z0-9+/=]+~>', code)
    decoded_results['ascii85_decoded'] = decode_ascii85(ascii85_strings)

    brotli_strings = detect_brotli(code)
    decoded_results['brotli_decoded'] = decode_brotli(brotli_strings)

    atbash_strings = re.findall(r'[A-Za-z]{5,}', code)
    decoded_results['atbash_decoded'] = decode_atbash(atbash_strings)

    morse_strings = re.findall(r'([.-/]+)', code)
    decoded_results['morse_decoded'] = decode_morse(morse_strings)

    base58_strings = detect_base58(code)
    decoded_results['base58_decoded'] = decode_base58(base58_strings)

    return decoded_results

code = '...'  # Example input string (encoded or scrambled text)
results = analyze_and_decode(code)
print(results)