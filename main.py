from wep_rc4_chop_chop.wep_rc4 import *

if __name__ == '__main__':
    # Variables (You would want to play here and change the values)
    # For now, cleartext and injection have to be of same length

    # inject_message = "is modified!"
    plaintext = b"My cleartext"
    secret_key = b"Key"
    inject_message = b"is modified!"

    plain = bytearray()
    plain.extend(plaintext)

    # Secret
    key = bytearray()
    key.extend(secret_key)

    injection = bytearray()
    injection.extend(inject_message)

    #
    #
    #
    print("Testing WEP RC4 encryption ...")
    f_iv, f_crc, f_cipher = frame = wep_make_frame(Bits(plain), Bits(key))
    print(frame)
    print("Frame Validity : " + str(frame.is_valid(Bits(key))))
    print("")

    #
    #
    #
    print("Testing WEP RC4 decryption ...")
    try:
        clear = wep_rc4_decrypt(Bits(key), frame)

        if clear == plaintext:
            print("Success !")
            print("Decrypted payload : " + str(clear))
        else:
            print("Failed to correctly decrypt :(")

    except ValueError as e:
        print("[ERROR] Decryption failed.", str(e))

    #
    #
    #
    print("Testing WEP frame message injection...")
    try:
        assert len(plain) == len(injection)
    except AssertionError:
        print("For now only injection messages of same length as plaintext are accepted. Injection Aborted.")
        exit(0)

    malicious_frame = wep_inject(Bits(injection), frame)
    print("Injected Frame :")
    print(malicious_frame)
    print("Injected Frame Validity : " + str(malicious_frame.is_valid(Bits(key))))

    try:
        clear = wep_rc4_decrypt(Bits(key), malicious_frame)
    except ValueError as e:
        print("[ERROR] Decryption failed.", str(e))

    # Other way of testing
    # Test if decrypted message is effectively the xor value of initial message and inject message
    try:
        clear
    except NameError:
        clear = bytearray()

    compare = bytearray()
    for i in range(max(len(plain), len(injection))):
        if i >= len(plain):
            compare.extend(injection[i:i + 1])
        else:
            if i >= len(injection):
                compare.extend(plain[i:i + 1])
            else:
                compare.extend((plain[i] ^ injection[i]).to_bytes(1, byteorder='big'))
    if malicious_frame.is_valid(Bits(key)) and clear == compare:
        print("Successful injection !")
    else:
        print("Injection failed :(")

    exit(0)
