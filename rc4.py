from os import urandom
from sys import version_info

if version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")


class Frame:

    def __init__(self, iv, crc, payload):
        self.iv = iv
        self.crc = crc
        self.payload = payload

    def is_valid(self, key):
        """
        (copy) Reduced function of below "rc4_decrypt"
        Returns True or False whether the Frame is valid, i.e. its crc32 is coherent to the message transported
        :param key:
        :return: True or False
        """
        ivk = self.iv
        ivk.extend(key)
        d = rc4_crypt(self.payload, ivk)
        m = d[:-len(self.crc)]
        crc = d[-len(self.crc):]
        c_crc = crc32(m)
        return self.crc == crc == c_crc

    def __iter__(self):
        yield self.iv
        yield self.crc
        yield self.payload


def byte_to_string(array: bytearray):
    """
    Given a bytearray, returns the assembling string representation
    :param array:
    :return:
    """
    return ''.join(chr(x) for x in array)


def byte_to_list(array: bytearray):
    num = []
    for i in range(len(array)):
        num.append(array[i])
    return num


def crc32(m):
    """
    Calculates the CRC32 value of message m
    :param m:
    :return: bytearray
    """
    remainder = int("0xFFFFFFFF", 16)
    qx = int("0xEDB88320", 16)

    for i in range(len(m) * 8):
        bit = (m[i // 8] >> (i % 8)) & 1
        remainder ^= bit
        if remainder & 1:
            multiple = qx
        else:
            multiple = 0
        remainder >>= 1
        remainder ^= multiple

    return bytearray((~remainder % (1 << 32)).to_bytes(4, byteorder='big'))


def rc4_extended_crc32(m):
    """
    Given a message m, returns encoding of (as by X^32 . m(X)) and the CRC32 of m
    :param m:
    :return:
    """
    ex_crc = bytearray()
    ex_crc.extend(m)
    ex_crc.extend(crc32(m))
    return ex_crc


def rc4_ksa(key):
    """
    Key-Scheduling Algorithm
    Given a key, returns the RC4 register after initilisation phase.
    :param key:
    :return r: rc4 initialised register
    """
    w = 256
    r = list(range(w))
    keylength = len(key)

    j = 0
    for i in range(w):
        j = (j + r[i] + key[i % keylength]) % w
        r[i], r[j] = r[j], r[i]

    return r


def rc4_prga(r, t):
    """
    Pseudo-random generation algorithm
    Given a register R and an integer t, returns a RC4 cipher stream of length t
    :param r:
    :type t: int
    :return:
    """
    w = 256
    i = j = 0

    for l in range(t):
        i = (i + 1) % w
        j = (j + r[i]) % w
        r[i], r[j] = r[j], r[i]

        k = r[(r[i] + r[j]) % w]
        yield k


def rc4_crypt(m: bytearray, k: bytearray):
    """
    RC4 Encryption
    Can be used for encryption and decryption
    Given a message m and key k, returns the rc4 de/encryption of m with key k
    :type m: bytearray
    :type k: bytearray
    :return:
    """
    length = len(m)
    result = bytearray()
    r = rc4_ksa(k)

    stream = rc4_prga(r, length)
    for l in range(length):
        """
        a = m[l]
        b = next(stream)
        c = a ^ b
        x = bytearray(c.to_bytes(1, byteorder='big'))
        """
        x = bytearray((m[l] ^ next(stream)).to_bytes(1, byteorder='big'))

        result.extend(x)

    return result


def wep_rc4_encrypt(m, k):
    """
    RC4 Encryption in WEP mode
    Given a message m and key k, returns the WEP implementation of the rc4 encryption of m with key k
    :type m
    :param k:
    :return:
     """
    iv = random_iv()
    # print("encrypt : iv : " + ''.join(chr(x) for x in iv))

    ivk = bytearray()
    ivk.extend(iv)
    ivk.extend(k)
    # print("encrypt : ivk : " + ''.join(chr(x) for x in ivk))

    cipher = rc4_crypt(m, ivk)

    return iv, cipher


def random_iv(length=24):
    """
    Returns a list of random bits, with default length 24.
    :param length:
    :return:
    """
    n_bytes = -(-length // 8)  # round up by upside down floor division
    return bytearray(urandom(n_bytes))


def wep_make_frame(m, key):
    """
    FR : Trame
    Given a message m and a key k, returns a frame, i.e. :
    - an IV, associated to the frame
    - a CRC32 of m (noted crc)
    - a WEP RC4 cipher of m || crc
    :param m:
    :param key:
    :return: IV, CRC, Cipher
    """
    crc = crc32(m)

    m_and_crc = bytearray(m)
    m_and_crc.extend(crc)

    iv, cipher = wep_rc4_encrypt(m_and_crc, key)

    return Frame(iv, crc, cipher)


def rc4_decrypt(k: bytearray, frame):
    """
    Given a key k and frame f, decrypts frame with key and returns cleartext.
    An error is raised if frame is not a valid frame.
    :type k: bytearray
    :type frame: Frame
    :return:
    """
    # Preprare key for decryption
    ivk = bytearray()
    ivk.extend(frame.iv)
    ivk.extend(k)

    # Decrypt
    decrypted_payload = rc4_crypt(frame.payload, ivk)

    # Get the cleartext and the crc that were in the encrypted packet
    cleartext_msg = decrypted_payload[:-len(frame.crc)]
    decrypted_crc = decrypted_payload[-len(frame.crc):]

    # Compute crc32 from decrypted message
    computed_crc = crc32(cleartext_msg)

    """
    print("check")
    print(byte_to_list(frame.crc))
    print(byte_to_list(computed_crc))
    print(byte_to_list(decrypted_crc))

    print("so ?" + str(frame.crc == computed_crc == decrypted_crc))
    print("so 2? " + str(frame.is_valid(k)))
    """

    # Check if Frame is valid by verifying crc32 fingerprints
    try:
        assert frame.crc == decrypted_crc == computed_crc
    except AssertionError:
        return "[ERROR] MAC ERROR. Invalid Frame (possibly corrupted). Cause : crc32 invalidation."

    print("Frame is valid.")
    return cleartext_msg


def check_crc_linearity(m1, m2):
    """
    Function to verify crc linearity
    :param m1:
    :param m2:
    :return:
    """
    import binascii
    # Build crc(m1) and crc( m1 || m2 )
    print("== Messages ==")
    print("m1 " + str(m1))
    print("m2 " + str(m2))
    crc_m1 = bytearray(binascii.crc32(m1).to_bytes(4, byteorder='little'))
    crc_m2 = bytearray(binascii.crc32(m2).to_bytes(4, byteorder='little'))
    print("== CRC 1 ==")
    print("crc_m1 " + str(byte_to_list(crc_m1)) + " " + str(crc_m1) + " " + str(len(crc_m1)))
    print("crc_m2 " + str(byte_to_list(crc_m2)) + " " + str(crc_m2) + " " + str(len(crc_m2)))

    # crc(m1||m2)
    mm = bytearray()
    mm.extend(m1)
    mm.extend(m2)
    print("== m1||m2 ==")
    print("m1||m2 " + str(byte_to_list(mm)) + " " + str(mm) + " " + str(len(mm)))

    print("== crc32(m1||m2) ==")
    crc_mm = bytearray(binascii.crc32(mm).to_bytes(4, byteorder='little'))
    print("crc32(m1||m2) " + str(byte_to_list(crc_mm)) + " " + str(crc_mm) + " " + str(len(crc_mm)))
    # print("crc_mm " + str(crc_mm))
    print("crc32(m1||m2) " + byte_to_string(crc_mm))

    # crc(m1) ^ crc(m2)
    print("== crc(m1) ^ crc(m2) ==")
    crc = bytearray()
    for i in range(len(crc_m1)):
        xor = crc_m1[i] ^ crc_m2[i]
        x = bytearray(xor.to_bytes(1, byteorder='little'))
        crc.extend(x)

    print("crc(m1) ^ crc(m2)   " + str(byte_to_list(crc)) + " " + str(crc) + " " + str(len(crc)))
    print("crc(m1) ^ crc(m2)   " + byte_to_string(crc))

    try:
        assert crc_mm == crc
        print("good")
    except AssertionError:
        print("[ERROR] CRC32 Linearity can not be verfied.")


def inject(m1: bytearray, m2: bytearray, m2f: Frame):
    """
    Given two messages m1 and m2, and the frame associated with m2 (as by the return values of wep_frame()),
    returns a valid frame for m1^m2

    === Trick ===
    Base :
        crc(m1^m2) = crc(m1) ^ crc(m2)

    Therefore :
        rc4(k||iv) ^ (  (m1^m2) || crc(m1^m2)  )
        = rc4(k||iv) ^ (m1 || crc(m1)) ^ (m2 || crc(m2))

    Conclusion :
        We finally have
        crc4( m1||crc(m1), k||iv) ^  (m2 || crc(m2))
        Meaning we can trivially inject something that would result in a valid frame

    What we will do here is, given a frame for m2, inject m1 to have a new valid frame

    :param m1:
    :param m2:
    :param m2f:
    :return:
    """

    # Get IV
    iv = m2f.iv

    # Get m1||CRC(m1)
    crc_ms1 = rc4_extended_crc32(m1)

    # Xor the message into frame payload
    payload = bytearray()
    length = len(crc_ms1)
    for i in range(length):
        payload.extend(bytearray((m2f.payload[i] ^ crc_ms1[i]).to_bytes(1, byteorder='big')))

    # Fresh Frame
    frame = Frame(iv, m1, payload)

    # Test if frame is valid
    k = "secret"
    b_k = bytearray()
    b_k.extend(k.encode())
    print("Success ? " + str(frame.is_valid(k.encode())))

    return frame


if __name__ == '__main__':
    # Plaintext
    plain1 = "abcdbcde"
    b_plain1 = bytearray()
    b_plain1.extend(plain1.encode())

    # Secret
    key1 = "secret"
    b_key1 = bytearray()
    b_key1.extend(key1.encode())

    # Encrypt
    f_iv, f_crc, f_cipher = f = wep_make_frame(b_plain1, b_key1)

    # Plaintext
    plain2 = "bcde"
    b_plain2 = bytearray()
    b_plain2.extend(plain2.encode())

    clear = rc4_decrypt(b_key1, f)
    print("valid ? " + str(f.is_valid(b_key1)))
    print("decrypted : " + byte_to_string(clear))

    print("== Check CRC Linearity ==")

    check_crc_linearity(b_plain1, b_plain2)

    print("== Check Injection Technique ==")

    inject(b_plain2, b_plain1, f)
