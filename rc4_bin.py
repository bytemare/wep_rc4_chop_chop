import sys
from os import urandom
from sys import version_info

from bitstring import Bits, BitArray

fun_name = sys._getframe().f_code.co_name

if version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")


class Frame:

    def __init__(self, iv, crc, payload):
        self.iv = iv
        self.crc = crc  # clair
        self.payload = payload  # chiffré

    def is_valid(self, key: Bits, verbose=True):
        """
        (copy) Reduced function of below "rc4_decrypt"
        Returns True or False whether the Frame is valid, i.e. its crc32 is coherent to the message transported
        :param verbose:
        :param key:
        :return: True or False
        """
        ivk = wep_make_ivk(key, self.iv)
        if verbose:
            debug(verbose, fun_name + " : ivk = " + str(ivk))

        decrypted = rc4_crypt(self.payload, ivk, verbose)
        if verbose:
            debug(verbose, fun_name + " : decrypted = " + str(ivk))

        decrypted_message = decrypted[:-len(self.crc)]
        if verbose:
            debug(verbose, fun_name + " : decrypted_message = " + str(decrypted_message))

        decrypted_crc = decrypted[-len(self.crc):]
        if verbose:
            debug(verbose, fun_name + " : decrypted_crc = " + str(decrypted_crc))

        int_computed_crc, computed_crc = crc32(decrypted_message)
        if verbose:
            debug(verbose, fun_name + " : computed_crc = " + str(computed_crc))
            debug(verbose, fun_name + " : computed_crc = " + str(int_computed_crc))
            debug(verbose, fun_name + " : frame_crc    = " + str(self.crc))

        return decrypted_crc == computed_crc

    def __iter__(self):
        yield self.iv
        yield self.crc
        yield self.payload

    def __str__(self):
        return "Initialisation Vector : " + str(self.iv) + "\nCRC32 : " + str(
            self.crc) + "\nEncrypted payload : " + str(self.payload)


def wep_make_ivk(key: Bits, iv: Bits, order="key+iv"):
    """
    Given a key and initialisation vector, returns the concatenation of both,
    depending on the order given by order (never sure what order it is)
    Default is to append vi to key.
    :param key:
    :param iv:
    :param order:
    :param debug:
    :return:
    """
    if order == "key+iv":
        return key + iv
    elif order == "iv+key":
        return iv + key
    else:
        raise ValueError("Unhandled value for argument 'orrder' : " + order + ". Try 'key+iv' or 'iv+key'.")


def debug(state, message):
    """
    If state is set to True, then message is printed. If not, nothing happens.
    :param state:
    :param message:
    :return:
    """
    if state:
        print(message)


def crc32(data: Bits):
    """
    Calculates the CRC32 value of message m
    :param data:
    :return: bytearray
    """

    m = bytearray(data.tobytes())

    remainder = int("0xFFFFFFFF", 16)
    # qx = int("0x04C11DB7", 16)
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

    result = ~remainder % (1 << 32)
    return result, Bits(uint=result, length=32)


def rc4_extended_crc32(m: Bits):
    """
    Given a message m, returns encoding of (as by X^32 . m(X)) and the CRC32 of m
    :param m:
    :return:
    """
    return m + crc32(m)[1]


def rc4_ksa(key_bits: Bits):
    """
    Key-Scheduling Algorithm
    Given a key, returns the RC4 register after initialisation phase.
    :param key_bits:
    :return r: rc4 initialised register
    """
    key = bytearray(key_bits.tobytes())
    w = 256
    r = list(range(w))
    keylength = len(key)

    j = 0
    for i in range(w):
        j = (j + r[i] + key[i % keylength]) % w
        r[i], r[j] = r[j], r[i]

    return r


def rc4_prga(r, t: int):
    """
    Pseudo-random generation algorithm
    Given a register R and an integer t, returns a RC4 cipher stream of length t
    :param stream:
    :param r:
    :type t: int
    :return:
    """
    w = 256
    i = j = 0
    s = BitArray()

    print("CHANGE THE STREAM LENGTH HERE !!!")
    t = t // 8

    for l in range(t):
        i = (i + 1) % w
        j = (j + r[i]) % w
        r[i], r[j] = r[j], r[i]

        k = r[(r[i] + r[j]) % w]
        s += Bits(bytearray(k.to_bytes(1, byteorder='big')))

    debug(True, fun_name + " : stream = " + str(s))
    return s


def rc4_crypt(m: Bits, k: Bits, verbose=True):
    """
    RC4 Encryption
    Can be used for encryption and decryption
    Given a message m and key k, returns the rc4 de/encryption of m with key k
    :param verbose:
    :type m: Bits
    :type k: Bits
    :return:
    """

    length = len(m)
    r = rc4_ksa(k)
    debug(verbose, fun_name + " : length = " + str(length))
    debug(verbose, fun_name + " : m (= " + str(m.len) + ") : " + str(m))
    debug(verbose, fun_name + " : r      = " + str(r))

    stream = rc4_prga(r, length)
    debug(verbose, fun_name + " : cipherstream (" + str(stream.len) + ") : " + str(stream))

    """
    s = Bits()
    a = bytearray()
    for l in range(length):
        n = next(stream)
        t = bytearray(n.to_bytes(1, byteorder='big'))
        a.extend(t)
        s += Bits(t)
    debug(verbose, fun_name + " : cipherstream(generator) = " + str(s))
    debug(verbose, fun_name + " : cipherstream(generator) = " + str(Bits(a)))
    """

    retained_stream = stream

    result = m ^ retained_stream

    debug(verbose, fun_name + " : key     = " + str(k))
    debug(verbose, fun_name + " : stream  = " + str(retained_stream))
    debug(verbose, fun_name + " : message = " + str(m))
    debug(verbose, fun_name + " : result  = " + str(result))

    return result


def random_iv(length=24):
    """
    Returns a list of random bits, with default length 24.
    :param length:
    :return: Bits
    """
    n_bytes = -(-length // 8)  # round up by upside down floor division
    return Bits(urandom(n_bytes))


def wep_rc4_encrypt(m: Bits, k: Bits, verbose=True):
    """
    RC4 Encryption in WEP mode
    Given a message m and key k, returns the WEP implementation of the rc4 encryption of m with key k
    :type m
    :param k:
    :return:
     """

    iv = random_iv()
    debug(verbose, fun_name + " : iv  = " + str(iv))

    ivk = wep_make_ivk(k, iv)
    debug(verbose, fun_name + " : ivk  = " + str(ivk))

    cipher = rc4_crypt(m, ivk)
    debug(verbose, fun_name + " : cipher  = " + str(cipher))

    return iv, cipher


def wep_make_frame(m: Bits, key: Bits, verbose=True):
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
    crc = crc32(m)[1]
    debug(verbose, fun_name + " : crc  = " + str(crc))

    m_and_crc = m + crc
    debug(verbose, fun_name + " : m_and_crc  = " + str(m_and_crc))

    iv, cipher = wep_rc4_encrypt(m_and_crc, key)

    return Frame(iv, crc, cipher)


def rc4_decrypt(k: Bits, frame: Frame, verbose=True):
    """
    Given a key k and frame f, decrypts frame with key and returns cleartext.
    An error is raised if frame is not a valid frame.
    :type k: bytearray
    :type frame: Frame
    :return:
    """
    # Preprare key for decryption
    ivk = wep_make_ivk(k, frame.iv)
    debug(verbose, fun_name + " : ivk  = " + str(ivk))

    # Decrypt
    decrypted_payload = rc4_crypt(frame.payload, ivk)
    debug(verbose, fun_name + " : decrypted_payload  = " + str(decrypted_payload))

    # Get the cleartext and the crc that were in the encrypted packet
    cleartext_msg = decrypted_payload[:-len(frame.crc)]
    decrypted_crc = decrypted_payload[-len(frame.crc):]
    debug(verbose, fun_name + " : cleartext_msg  = " + str(cleartext_msg))
    debug(verbose, fun_name + " : decrypted_crc  = " + str(decrypted_crc))

    # Compute crc32 from decrypted message
    computed_crc = crc32(cleartext_msg)[1]
    debug(verbose, fun_name + " : computed_crc  = " + str(computed_crc))

    # Check if Frame is valid by verifying crc32 fingerprints
    try:
        assert decrypted_crc == computed_crc
    except AssertionError:
        return "[ERROR] MAC ERROR. Invalid Frame (possibly corrupted). Cause : crc32 invalidation."

    debug(verbose, fun_name + " : Frame is valid.")
    return cleartext_msg


def mix_crc(a: Bits, b: Bits, c: Bits, verbose=True):
    """
    Given 3 bytearrays, returns the xor between the 3 crcs of the input data
    :param a:
    :param b:
    :param c:
    :return:
    """
    i_a_crc, _ = crc32(a)
    i_b_crc, _ = crc32(b)
    i_c_crc, _ = crc32(c)

    xor = i_a_crc ^ i_b_crc ^ i_c_crc
    debug(verbose, fun_name + " : crc(a) ^ crc(b) ^ crc(c)  = " + str(xor))

    return xor


def prepend_zeros(data: bytes, length: int):
    """
    Given a bytes type input, returns it prepended with length '0'
    :param data:
    :param length:
    :return:
    """
    print("prepend " + str(length))
    return length * b"0" + data


def bin_inject(m_prime: Bits, m: Bits, frame, key: Bits, verbose=True):
    """
    Given two messages m1 and m2, and the frame associated with m2 (as by the return values of wep_frame()),
    returns a valid frame for m1^m2

    === Trick ===
    Base :
        crc(m1^m2^m3) = crc(m1) ^ crc(m2) ^ crc(m3)

        if you take m3 = 0, xoring the messages is like m1^m2.
        Hence,

        crc(m1^m2) = crc(m1) ^ crc(m2) ^ crc(0)

    Therefore :
        rc4(k||iv) ^ (  (m1^m2) || crc(m1^m2)  )
        = rc4(k||iv) ^ (m1 || crc(m1)) ^ (m2 || crc(m2) ^ ( crc(0) ))

    Conclusion :
        To inject, you simply xor the encrypted payload with
        inject_message || ( crc(inject_message) ^ crc(0) )

        In decryption, this would give the following
        decrypted payload : ( inject_message ^ m ) || ( crc(inject_message) ^ crc(m) ^ crc(0) )

        Since we have
        crc(inject_message ^ m) = crc(inject_message) ^ crc(m) ^ crc(0)

        The decrypted message is considered valid.
    =============

    What we will do here is, given a frame for message m, inejcted the message 'inject_message

    :param m_prime:
    :param m:
    :param frame:
    :return:
    """
    reference_length = len(frame.payload) - len(frame.crc)
    debug(verbose, fun_name + " : reference_length = " + str(reference_length))

    inject = m_prime
    debug(verbose, fun_name + " : inject length = " + str(inject.len))
    inject_crc_bits = crc32(m_prime)[1]

    zero_bits = Bits((reference_length // 8) * b"\0")
    debug(verbose, fun_name + " : zero length = " + str(zero_bits.len))
    zero_crc_bits = crc32(zero_bits)[1]
    debug(verbose, fun_name + " : zero_bits = " + str(zero_bits))
    debug(verbose, fun_name + " : zero_crc_bits = " + str(zero_crc_bits))

    debug(verbose, fun_name + " : inject = " + str(inject))
    debug(verbose, fun_name + " : inject^0 = " + str(inject ^ zero_bits))

    m_crc_bits = crc32(m)[1]

    inject_crc_suffix = inject_crc_bits ^ zero_crc_bits
    debug(verbose, fun_name + " : inject_crc_suffix = " + str(inject_crc_suffix))

    resulting_crc = inject_crc_suffix ^ m_crc_bits
    debug(verbose, fun_name + " : resulting_crc = " + str(resulting_crc))

    xored_payload_without_zero = m ^ inject
    xored_payload_with_zero = m ^ inject ^ zero_bits
    debug(verbose, fun_name + " : xored_payload_wo_zero = " + str(xored_payload_without_zero))
    debug(verbose, fun_name + " : xored_payload_w_zero  = " + str(xored_payload_with_zero))

    computed_crc_wo_zero = crc32(xored_payload_without_zero)[1]
    computed_crc_w_zero = crc32(xored_payload_with_zero)[1]

    debug(verbose, fun_name + " : computed_crc_wo_zero = " + str(computed_crc_wo_zero))
    debug(verbose, fun_name + " : computed_crc_w_zero  = " + str(computed_crc_w_zero))
    debug(verbose, fun_name + " : inject_crc_suffix    = " + str(inject_crc_suffix))

    result_payload = frame.payload ^ (inject + inject_crc_suffix)

    debug(verbose, fun_name + "### Verification ...")

    ivk = wep_make_ivk(key, frame.iv)
    r = rc4_ksa(ivk)
    # stream = rc4_prga(r, len(m))

    # cipherstream = frame.payload ^ (m + m_crc_bits)

    return Frame(frame.iv, resulting_crc, result_payload)


if __name__ == '__main__':
    # Variables (You would want to play here and change the values)
    # plaintext = "My cleartext"
    # secret_key = "Key"

    # inject_message = "is modified!"
    plaintext = b"000yay"
    secret_key = b"c"
    inject_message = b"secret"

    print("=== Test Run ===")
    print("=> Plaintext : " + str(plaintext))
    print("=> secret : " + str(secret_key))
    print("=> injection message : " + str(inject_message))

    print("")
    print("### Setting parameters ...")

    # Plaintext
    plain = bytearray()
    plain.extend(plaintext)

    # Secret
    key = bytearray()
    key.extend(secret_key)

    injection = bytearray()
    injection.extend(inject_message)

    print("")
    print("### 1. Executing CRC32:=proc(M) ###")

    print("CRC32(plaintext) = " + str(crc32(Bits(plain))[0]))

    print("")
    print("### 2. Executing RC4KSA:=proc(K) ###")
    r = rc4_ksa(Bits(key))
    print("RC4KSA(key) = " + str(r))

    print("")
    print("### 3. Executing RC4PRGA:=proc(R, t) ###")
    stream = list(rc4_prga(r, len(plaintext)))
    print("RC4PRGA(R, t) = " + str(stream))

    print("")
    print("### 4. Executing RC4:=proc(M, K) ###")
    rc4 = rc4_crypt(Bits(plain), Bits(key))
    print("RC4(M, K) = " + str(rc4))

    print("")
    print("### 5. Executing RandomIV:=proc() ###")
    iv = random_iv()
    print("RandomIV() = " + str(iv))

    print("")
    print("### 6. Executing Trame:=proc(M, K) ###")
    f_iv, f_crc, f_cipher = frame = wep_make_frame(Bits(plain), Bits(key), verbose=True)
    print(frame)
    print("Frame Validity : " + str(frame.is_valid(Bits(key))))

    print("")
    print("### 7. Executing Decrypt:=proc(K, T) ###")
    clear = rc4_decrypt(Bits(key), frame)
    if clear == plaintext:
        print("Success !")
    else:
        print("Failed to correctly decrypt :(")
    print("Decrypted payload : " + str(clear))

    print("")
    print("### 8. Executing Inject:=proc(K, T) ###")

    try:
        assert len(plain) == len(injection)
    except AssertionError:
        print("For now only injection messages of same length as plaintext are accepted. Injection Aborted.")
        exit(0)

    # new_frame = bin_inject(Bits(injection), Bits(plain), frame, Bits(key), True)
    # print("New Frame :")
    # print(new_frame)
    # print("Frame Validity : " + str(new_frame.is_valid(key, True)))

    bin_frame = bin_inject(Bits(injection), Bits(plain), frame, Bits(key), True)
    print("Injected Frame :")
    print(bin_frame)
    print("Injected Frame Validity : " + str(bin_frame.is_valid(Bits(key), True)))

    clear = rc4_decrypt(Bits(key), bin_frame)
    try:
        print("decrypted : " + str(clear))
    except TypeError:
        print(clear)
    compare = bytearray()
    for i in range(max(len(plain), len(injection))):
        if i >= len(plain):
            print("correct this")  # compare.extend(inject[i:i + 1])
        else:
            if i >= len(injection):
                compare.extend(plain[i:i + 1])
            else:
                compare.extend((plain[i] ^ injection[i]).to_bytes(1, byteorder='big'))
    if bin_frame.is_valid(Bits(key)) and clear == compare:
        print("Successfull injection !")
    else:
        print("Injection failed :(")

    exit(0)
