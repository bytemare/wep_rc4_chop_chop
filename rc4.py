from sys import version_info, _getframe

from bitstring import Bits, BitArray

if version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

fun_name = _getframe().f_code.co_name

if version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")


def crc32(data: Bits):
    """
    Calculates the CRC32 value of message m
    :param data:
    :return: bitstring
    """

    m = bytearray(data.tobytes())

    remainder = int("0xFFFFFFFF", 16)
    qx = int("0xEDB88320", 16)

    for b in range(len(m) * 8):
        bit = (m[b // 8] >> (b % 8)) & 1
        remainder ^= bit
        if remainder & 1:
            multiple = qx
        else:
            multiple = 0
        remainder >>= 1
        remainder ^= multiple

    result = ~remainder % (1 << 32)
    return Bits(uint=result, length=32)


def rc4_ksa(key_bits: Bits):
    """
    Key-Scheduling Algorithm
    Given a key, returns the RC4 register after initialisation phase.
    :param key_bits:
    :return r: rc4 initialised register
    """
    k = bytearray(key_bits.tobytes())
    w = 256
    r = list(range(w))
    key_length = len(k)

    j = 0
    for i in range(w):
        j = (j + r[i] + k[i % key_length]) % w
        r[i], r[j] = r[j], r[i]

    return r


def rc4_prga(s, t: int):
    """
    Pseudo-random generation algorithm
    Given a register R and an integer t, returns a RC4 cipher stream of length t.

    Warning : t is in the length of characters, not the number of bits. So be sure to accordingly divide by 8.

    :param s:
    :type t: int
    :return:
    """
    w = 256
    c = j = 0
    cs = BitArray()

    for l in range(t):
        c = (c + 1) % w
        j = (j + s[c]) % w
        s[c], s[j] = s[j], s[c]

        k = s[(s[c] + s[j]) % w]
        cs += Bits(bytearray(k.to_bytes(1, byteorder='big')))

    return cs


def rc4_crypt(data: Bits, k: Bits):
    """
    RC4 Encryption
    Can be used for encryption and decryption
    Given a message and a key, returns the rc4 de/encryption of data with key k
    :type data: Bits
    :type k: Bits
    :return:
    """
    s = rc4_ksa(k)
    return data ^ rc4_prga(s, len(data) // 8)
