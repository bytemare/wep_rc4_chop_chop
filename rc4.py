from os import urandom
from sys import version_info

if version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")


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


def rc4_crc32(m):
    """
    Given a message m, returns encoding of (as by X^32 . m(X)) and the CRC32 of m
    :param m:
    :return:
    """
    encoded = bytearray(m)
    crc = bytearray()
    crc.extend(crc32(m))
    return encoded, crc


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


def rc4_encrypt(m, k):
    """
    RC4 Encryption
    Given a message m and key k, returns the rc4 encryption of m with key k
    :param length:
    :type m
    :param k:
    :return:
    """
    length = len(m)
    result = bytearray()
    r = rc4_ksa(k)

    print("length : " + str(length))

    stream = rc4_prga(r, length)
    for l in range(length):
        a = m[l]
        b = next(stream)
        c = a ^ b

        # x = bytearray((m[l] ^ next(stream)).to_bytes(2, byteorder='big'))
        x = bytearray(c.to_bytes(1, byteorder='big'))
        # print("Encrypt : " + str(a.to_bytes(1, byteorder='big')) + " ^ " + str(b.to_bytes(1, byteorder='big')) + " = " + str(c.to_bytes(1, byteorder='big')) + "( " + str(x) + "/" + ''.join(chr(d) for d in x) + " )")
        # print("Encrypt : " + str(a) + " ^ " + str(b) + " = " + str(c) + "( " + str(x) + "/" + ''.join(
        #    chr(d) for d in x) + " )")

        result.extend(x)

    print("Encrypt : result length : " + str(len(result)))
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

    cipher = rc4_encrypt(m, ivk)

    return iv, cipher


def random_iv(length=24):
    """
    Returns a list of random bits, with default length 24.
    :param length:
    :return:
    """
    n_bytes = -(-length // 8)  # round up by upside down floor division
    return bytearray(urandom(n_bytes))


def wep_frame(m, key):
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
    enc, crc = rc4_crc32(m)

    m_and_crc = bytearray(m)
    m_and_crc.extend(crc)

    iv, cipher = wep_rc4_encrypt(m_and_crc, key)

    print("cipher : " + str(cipher))
    print("cipher : " + ''.join(chr(x) for x in cipher))
    return iv, crc, cipher


def rc4_decrypt(k, f):
    """
    Given a key k and frame f, decrypts frame with key and returns cleartext.
    An error is raised if frame is not a valid frame.
    :param k:
    :param f:
    :return:
    """
    iv, crc, cipher = f
    ivk = bytearray()
    ivk.extend(iv)
    ivk.extend(k)
    clear = rc4_encrypt(cipher, ivk)
    payload = clear[:-len(crc)]
    dec_crc = clear[-len(crc):]

    print("check")
    print(byte_to_list(crc))
    new = crc32(payload)
    print(byte_to_list(new))
    print(byte_to_list(dec_crc))

    print("so ?" + str(crc == new == dec_crc))

    return "yo"


def inject(m1, m2, m2f):
    """
    Given two messages m1 and m2, and the frame associated with m2 (as by the return values of wep_frame()),
    returns a valid frame for m1^m2
    :param m1:
    :param m2:
    :param m2f:
    :return:
    """

    return


if __name__ == '__main__':
    plain1 = "plaintext"
    b_plain1 = bytearray()
    b_plain1.extend(plain1.encode())
    key1 = "secret"
    b_key1 = bytearray()
    b_key1.extend(key1.encode())
    f_iv, f_crc, f_cipher = f = wep_frame(b_plain1, b_key1)
    print("IV : " + str(f_iv))
    print("IV : " + ''.join(chr(x) for x in f_iv))
    # print("crc : " + crc.decode())
    print("cipher : " + ''.join(chr(x) for x in f_cipher))

    clear = rc4_decrypt(b_key1, f)
    print("cleartext : " + ''.join(chr(x) for x in clear))
