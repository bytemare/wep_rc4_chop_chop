import bitstring

from wep_rc4_chop_chop.wep_rc4 import *

if __name__ == '__main__':
    # Variables (You would want to play here and change the values)
    # For now, cleartext and injection have to be of same length

    # inject_message = "is modified!"
    plaintext = b"My cleartext"
    secret_key = 7038329
    inject_message = "is modified!"

    plain = bitstring.Bits(plaintext)
    key = bitstring.Bits(uint=secret_key, length=24)  # length of input in bits
    injection = bitstring.Bits(inject_message.encode())

    #
    #
    #
    print("Testing WEP RC4 encryption ...")
    f_iv, f_crc, f_cipher = frame = wep_make_frame(plain, key)
    print(frame)
    print("Frame Validity : " + str(frame.is_valid(Bits(key))))
    print("")

    #
    #
    #
    print("Testing WEP RC4 decryption ...")
    try:
        clear = frame.decrypt(key)

        if clear == plaintext:
            print("Success !")
            print("Decrypted payload : " + str(clear))
        else:
            print("Failed to correctly decrypt :(")

    except ValueError as e:
        print("[ERROR] Decryption failed.", str(e))
    print("")

    #
    #
    #
    print("Testing WEP frame message injection...")
    try:
        assert len(plain) == len(injection)
    except AssertionError:
        print("For now only injection messages of same length as plaintext are accepted. Injection Aborted.")
        exit(0)

    malicious_frame = wep_inject(injection, frame)
    print("Injected Frame :")
    print(malicious_frame)
    print("Injected Frame Validity : " + str(malicious_frame.is_valid(key)))

    clear = Bits()
    try:
        clear = malicious_frame.decrypt(key)
        print("Decrypted payload : " + str(clear))
    except ValueError as e:
        print("[ERROR] Decryption failed.", str(e))

    # Other way of testing
    # Test if decrypted message is effectively the xor value of initial message and inject message
    xor = plain ^ injection
    crc_xor = crc32(xor)
    crc_clear = crc32(clear)

    if clear == xor and crc_xor == crc_clear:
        print("Successful injection !")
    else:
        print("Injection failed :(")

    exit(0)
