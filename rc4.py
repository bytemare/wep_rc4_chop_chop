from sys import version_info

if version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")


class Frame:

    def __init__(self, iv, crc, payload):
        self.iv = iv
        self.crc = crc  # clair
        self.payload = payload  # chiffré

    def is_valid(self, key: bytearray, debug=False):
        """
        (copy) Reduced function of below "rc4_decrypt"
        Returns True or False whether the Frame is valid, i.e. its crc32 is coherent to the message transported
        :param key:
        :return: True or False
        """
        ivk = key[:]
        ivk.extend(self.iv)
        d = rc4_crypt(self.payload, ivk)

        m = d[:-len(self.crc)]
        if debug: print("m : " + str(byte_to_list(m)) + " " + str(m) + " " + str(len(m)))

        if debug: print("self.crc : " + str(byte_to_list(self.crc)) + " " + str(self.crc) + " " + str(len(self.crc)))

        crc = d[-len(self.crc):]
        if debug: print("crc : " + str(byte_to_list(crc)) + " " + str(crc) + " " + str(len(crc)))
        _, c_crc = crc32(m)
        if debug: print("c_crc : " + str(byte_to_list(c_crc)) + " " + str(c_crc) + " " + str(len(c_crc)))

        return crc == c_crc

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


def crc32(m: bytearray):
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

    result = ~remainder % (1 << 32)
    return result, bytearray(result.to_bytes(4, byteorder='big'))


def rc4_extended_crc32(m: bytearray):
    """
    Given a message m, returns encoding of (as by X^32 . m(X)) and the CRC32 of m
    :param m:
    :return:
    """
    ex_crc = bytearray()
    ex_crc.extend(m)
    ex_crc.extend(crc32(m)[1])
    return ex_crc


def rc4_ksa(key: bytearray):
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


def rc4_prga(r, t: int):
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


def rc4_crypt(m: bytearray, k: bytearray, debug=False):
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
    s = bytearray()
    for l in range(length):
        a = next(stream)
        s.extend(a.to_bytes(1, byteorder='big'))
        x = bytearray((m[l] ^ a).to_bytes(1, byteorder='big'))
        result.extend(x)

    if debug: print("key : " + str(byte_to_list(k)) + " " + str(k) + " " + str(len(k)))
    if debug: print("encryption stream : " + str(byte_to_list(s)) + " " + str(s) + " " + str(len(s)))
    if debug: print("message : " + str(byte_to_list(m)) + " " + str(m) + " " + str(len(m)))
    if debug: print("result : " + str(byte_to_list(result)) + " " + str(result) + " " + str(len(result)))

    return result


def random_iv(length=24):
    """
    Returns a list of random bits, with default length 24.
    :param length:
    :return:
    """
    n_bytes = -(-length // 8)  # round up by upside down floor division
    return bytearray("abc".encode())  # , urandom(n_bytes))


def wep_rc4_encrypt(m: bytearray, k: bytearray):
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
    ivk.extend(k)
    ivk.extend(iv)
    # print("encrypt : ivk : " + ''.join(chr(x) for x in ivk))

    cipher = rc4_crypt(m, ivk)

    return iv, cipher


def wep_make_frame(m: bytearray, key: bytearray):
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

    m_and_crc = bytearray(m)
    m_and_crc.extend(crc)

    iv, cipher = wep_rc4_encrypt(m_and_crc, key)

    return Frame(iv, crc, cipher)


def rc4_decrypt(k: bytearray, frame: Frame):
    """
    Given a key k and frame f, decrypts frame with key and returns cleartext.
    An error is raised if frame is not a valid frame.
    :type k: bytearray
    :type frame: Frame
    :return:
    """
    # Preprare key for decryption
    ivk = bytearray()
    ivk.extend(k)
    ivk.extend(frame.iv)


    # Decrypt
    decrypted_payload = rc4_crypt(frame.payload, ivk)

    # Get the cleartext and the crc that were in the encrypted packet
    cleartext_msg = decrypted_payload[:-len(frame.crc)]
    decrypted_crc = decrypted_payload[-len(frame.crc):]

    # Compute crc32 from decrypted message
    computed_crc = crc32(cleartext_msg)[1]

    # Check if Frame is valid by verifying crc32 fingerprints
    try:
        assert frame.crc == decrypted_crc == computed_crc
    except AssertionError:
        return "[ERROR] MAC ERROR. Invalid Frame (possibly corrupted). Cause : crc32 invalidation."

    # print("Frame is valid.")
    return cleartext_msg


def check_crc_linearity(m1: bytearray, m2: bytearray):
    """
    Function to verify crc linearity property : crc(m1+m2) = crc(m1) ^ crc(m2)
    :param m1:
    :param m2:
    :return:
    """
    """
    # Normalise messages to same size
    m1 = m1_
    m2 = m2_

    if len(m1) > len(m2):
        print("1 is longer")
        m2 = bytearray(len(m1))
        print("m2 " + str(byte_to_list(m2)) + " " + str(m2) + " " + str(len(m2)))
        m2[-len(m1):] = m2_
        print("m2 " + str(byte_to_list(m2)) + " " + str(m2) + " " + str(len(m2)))
    elif len(m2) > len(m1):
        print("2 is longer")
        m1_ = bytearray(len(m2))
        m1[-len(m1):] = m1_
    """

    i_crc_m1, crc_m1 = crc32(m1)  # bytearray(crc32(m1)[1])
    i_crc_m2, crc_m2 = crc32(m2)  # bytearray(crc32(m2)[1])

    add_crc_p = i_crc_m1 + i_crc_m2
    add_crc_x = i_crc_m1 ^ i_crc_m2

    print("add_crc_p + " + str(add_crc_p))
    print("add_crc_x ^ " + str(add_crc_x))

    i_add_x = m1[0] ^ m2[0]
    print("i_add ^ " + str(i_add_x))
    i_add_p = m1[0] + m2[0]
    print("i_add + " + str(i_add_p))

    crc_add_p = crc32(bytearray(i_add_p.to_bytes(1, byteorder='big')))[0]
    crc_add_x = crc32(bytearray(i_add_x.to_bytes(1, byteorder='big')))[0]

    print("crc_add_p " + str(crc_add_p))
    print("crc_add_x " + str(crc_add_x))





    # Build crc(m1) and crc( m1 || m2 )
    print("== Messages ==")
    print("m1 " + str(m1))
    print("m2 " + str(m2))
    print("")
    print("m1 " + str(byte_to_list(m1)) + " " + str(m1) + " " + str(len(m1)))
    print("m2 " + str(byte_to_list(m2)) + " " + str(m2) + " " + str(len(m2)))
    i_crc_m1, crc_m1 = crc32(m1)  # bytearray(crc32(m1)[1])
    i_crc_m2, crc_m2 = crc32(m2)  # bytearray(crc32(m2)[1])
    print("== CRC 1 ==")
    print("crc_m1 " + str(i_crc_m1) + " " + str(byte_to_list(crc_m1)) + " " + str(crc_m1) + " " + str(len(crc_m1)))
    print("crc_m2 " + str(i_crc_m2) + " " + str(byte_to_list(crc_m2)) + " " + str(crc_m2) + " " + str(len(crc_m2)))

    # crc(m1+m2)

    print("max ")

    mm = bytearray(max(len(m1), len(m2)))
    alt = None
    if len(m1) >= len(m2):
        mm[:] = m1
        alt = m2
    elif len(m2) > len(m1):
        mm[:] = m2
        alt = m1

    print("mm " + str(byte_to_list(mm)) + " " + str(mm) + " " + str(len(mm)))
    print("alt " + str(byte_to_list(alt)) + " " + str(alt) + " " + str(len(alt)))

    for i in range(min(len(m1), len(m2))):
        print("i : " + str(i) + " / " + str(min(len(m1), len(m2))))

        print("mm " + str(mm[i]))
        print("alt " + str(alt[i]))
        x = mm[i] + alt[i]

        mm[i] = x
    # mm.extend(m1)
    # mm.extend(m2)
    print("== m1+m2 ==")
    print("m1+m2 " + str(byte_to_list(mm)) + " " + str(mm) + " " + str(len(mm)))

    print("== crc32(m1+m2) ==")
    i_crc_mm, crc_mm = crc32(mm)
    print("crc32(m1+m2) " + str(i_crc_mm) + " " + str(byte_to_list(crc_mm)) + " " + str(crc_mm) + " " + str(len(crc_mm)))
    # print("crc_mm " + str(crc_mm))
    print("crc32(m1+m2) " + byte_to_string(crc_mm))

    # crc(m1) ^ crc(m2)
    print("== crc(m1) ^ crc(m2) ==")
    crc = bytearray()
    for i in range(len(crc_m1)):
        xor = crc_m1[i] ^ crc_m2[i]
        x = bytearray(xor.to_bytes(1, byteorder='big'))
        crc.extend(x)

    i_crc = i_crc_m1 ^ i_crc_m2
    print("i_crc = " + str(i_crc))

    print("crc(m1) ^ crc(m2)   " + str(byte_to_list(crc)) + " " + str(crc) + " " + str(len(crc)))
    print("crc(m1) ^ crc(m2)   " + byte_to_string(crc))

    try:
        assert crc_mm == crc
        print("good")
    except AssertionError:
        print("[ERROR] CRC32 Linearity can not be verfied.")


def homebrew(m1, m2, m2f, debug=False):
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

    What we will do here is, given a frame for m2, inject m1 and get a new valid frame

    :param m1:
    :param m2:
    :param m2f:
    :return:
    """

    k = "Key"
    b_k = bytearray()
    b_k.extend(k.encode())
    if debug: print("new Valid Frame : " + str(m2f.is_valid(b_k)))

    m1 = m1
    m1_crc = crc32(m1)[1]
    m1_crc_ex = rc4_extended_crc32(m1)
    if debug: print("m1 : " + str(byte_to_list(m1)) + " " + str(m1) + " " + str(len(m1)))
    if debug: print("m1_crc : " + str(byte_to_list(m1_crc)) + " " + str(m1_crc) + " " + str(len(m1_crc)))
    if debug: print("m1_crc_ex : " + str(byte_to_list(m1_crc_ex)) + " " + str(m1_crc_ex) + " " + str(len(m1_crc_ex)))

    m2 = m2
    m2_crc = crc32(m2)[1]
    m2_crc_ex = rc4_extended_crc32(m2)
    if debug: print("m2 : " + str(byte_to_list(m2)) + " " + str(m2) + " " + str(len(m2)))
    if debug: print("m2_crc : " + str(byte_to_list(m2_crc)) + " " + str(m2_crc) + " " + str(len(m2_crc)))
    if debug: print("m2_crc_ex : " + str(byte_to_list(m2_crc_ex)) + " " + str(m2_crc_ex) + " " + str(len(m2_crc_ex)))

    crc_xor = bytearray()
    for x in range(len(m1_crc)):
        crc_xor.extend((m1_crc[x] ^ m2_crc[x]).to_bytes(1, byteorder='big'))
    if debug: print("crc_xor : " + str(byte_to_list(crc_xor)) + " " + str(crc_xor) + " " + str(len(crc_xor)))

    mxm = bytearray(max(len(m1), len(m2)))
    alt = None
    if len(m1) >= len(m2):
        mxm[:] = m1
        alt = m2
    else:
        mxm[:] = m2
        alt = m1
    for i in range(min(len(m1), len(m2))):
        mxm[i] = mxm[i] ^ alt[i]

    mpm = bytearray()
    mpm.extend(m1)
    mpm.extend(m2)
    mpm_crc = crc32(mpm)[1]
    if debug: print("mpm_crc : " + str(byte_to_list(mpm_crc)) + " " + str(mpm_crc) + " " + str(len(mpm_crc)))

    mxm_crc = crc32(mxm)[1]
    mxm_crc_ex = rc4_extended_crc32(mxm)
    if debug: print("mxm : " + str(byte_to_list(mxm)) + " " + str(mxm) + " " + str(len(mxm)))
    if debug: print("mxm_crc : " + str(byte_to_list(mxm_crc)) + " " + str(mxm_crc) + " " + str(len(mxm_crc)))
    if debug: print(
        "mxm_crc_ex : " + str(byte_to_list(mxm_crc_ex)) + " " + str(mxm_crc_ex) + " " + str(len(mxm_crc_ex)))

    if debug: print("computing charge 1...")
    charge = bytearray()
    for i in range(len(mxm_crc)):
        charge.extend((mxm_crc[i] ^ m2_crc[i]).to_bytes(1, byteorder='big'))
    if debug: print("charge : " + str(byte_to_list(charge)) + " " + str(charge) + " " + str(len(charge)))

    if debug: print("computing charge 2...")
    charge2 = bytearray()
    for i in range(len(mxm_crc)):
        c = m1_crc[i] | m2_crc[i]
        charge2.extend((c ^ m2_crc[i]).to_bytes(1, byteorder='big'))
    if debug: print("charge2 : " + str(byte_to_list(charge2)) + " " + str(charge2) + " " + str(len(charge2)))

    if debug: print("Getting stream ...")
    stream = bytearray()
    for l in range(len(m2_crc_ex)):
        x = bytearray((m2_crc_ex[l] ^ m2f.payload[l]).to_bytes(1, byteorder='big'))
        stream.extend(x)
    if debug: print("stream : " + str(byte_to_list(stream)) + " " + str(stream) + " " + str(len(stream)))

    if debug: print("Computing inject and encrypt...")
    payload = bytearray()
    inject = bytearray()
    inject.extend(m1)
    inject.extend(charge)
    for i in range(len(stream)):
        payload.extend((inject[i] ^ m2f.payload[i]).to_bytes(1, byteorder='big'))
    if debug: print("payload : " + str(byte_to_list(payload)) + " " + str(payload) + " " + str(len(payload)))

    new_Frame = Frame(m2f.iv, mxm_crc, payload)

    print("new Valid Frame : " + str(new_Frame.is_valid(b_k)))

    clear = rc4_decrypt(b_k, new_Frame)
    print("decrypted : " + byte_to_string(clear))


if __name__ == '__main__':
    # Variables (You would want to play here and change the values)
    plaintext = "plaintext"
    secret_key = "Key"

    inject_message = "modified!"

    # Plaintext
    b_plain1 = bytearray()
    b_plain1.extend(plaintext.encode())

    # Secret
    b_key1 = bytearray()
    b_key1.extend(secret_key.encode())

    # Encrypt
    f_iv, f_crc, f_cipher = f = wep_make_frame(b_plain1, b_key1)

    # Plaintext
    b_plain2 = bytearray()
    b_plain2.extend(inject_message.encode())

    clear = rc4_decrypt(b_key1, f)
    print("valid ? " + str(f.is_valid(b_key1)))
    print("decrypted : " + byte_to_string(clear))

    # print("== Check CRC Linearity ==")

    #check_crc_linearity(b_plain1, b_plain2)

    print("== Check Injection Technique ==")

    homebrew(b_plain2, b_plain1, f)
