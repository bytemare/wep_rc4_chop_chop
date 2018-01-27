from os import urandom
from sys import version_info

if version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")


class Frame:

    def __init__(self, iv, crc, payload):
        self.iv = iv
        self.crc = crc  # clair
        self.payload = payload  # chiffré

    def is_valid(self, key: bytearray, verbose=False):
        """
        (copy) Reduced function of below "rc4_decrypt"
        Returns True or False whether the Frame is valid, i.e. its crc32 is coherent to the message transported
        :param verbose:
        :param key:
        :return: True or False
        """
        ivk = key[:]
        ivk.extend(self.iv)
        decrypted = rc4_crypt(self.payload, ivk)
        debug(verbose,
              "payload : " + str(byte_to_list(self.payload)) + " " + str(self.payload) + " " + str(len(self.payload)))
        debug(verbose, "decrypted : " + str(byte_to_list(decrypted)) + " " + str(decrypted) + " " + str(len(decrypted)))

        message = decrypted[:-len(self.crc)]
        debug(verbose, "m : " + str(byte_to_list(message)) + " " + str(message) + " " + str(len(message)))

        debug(verbose, "self.crc : " + str(byte_to_list(self.crc)) + " " + str(self.crc) + " " + str(len(self.crc)))

        decrypted_crc = decrypted[-len(self.crc):]
        debug(verbose,
              "crc : " + str(byte_to_list(decrypted_crc)) + " " + str(decrypted_crc) + " " + str(len(decrypted_crc)))
        _, computed_crc = crc32(message)
        debug(verbose,
              "c_crc : " + str(byte_to_list(computed_crc)) + " " + str(computed_crc) + " " + str(len(computed_crc)))

        return decrypted_crc == computed_crc

    def __iter__(self):
        yield self.iv
        yield self.crc
        yield self.payload

    def __str__(self):
        return "Initialisation Vector : " + str(byte_to_list(self.iv)) + "\nCRC32 : " + str(
            byte_to_list(self.crc)) + "\nEncrypted payload : " + str(byte_to_list(self.payload))


def debug(state, message):
    """
    If state is set to True, then message is printed. If not, nothing happens.
    :param state:
    :param message:
    :return:
    """
    if state:
        print(message)


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
    qx = int("0x04C11DB7", 16)
    # qx = int("0xEDB88320", 16)

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


def rc4_crypt(m: bytearray, k: bytearray, verbose=False):
    """
    RC4 Encryption
    Can be used for encryption and decryption
    Given a message m and key k, returns the rc4 de/encryption of m with key k
    :param verbose:
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
        result.extend(bytearray((m[l] ^ a).to_bytes(1, byteorder='big')))

    debug(verbose, "key : " + str(byte_to_list(k)) + " " + str(k) + " " + str(len(k)))
    debug(verbose, "encryption stream : " + str(byte_to_list(s)) + " " + str(s) + " " + str(len(s)))
    debug(verbose, "message : " + str(byte_to_list(m)) + " " + str(m) + " " + str(len(m)))
    debug(verbose, "result : " + str(byte_to_list(result)) + " " + str(result) + " " + str(len(result)))

    return result


def random_iv(length=24):
    """
    Returns a list of random bits, with default length 24.
    :param length:
    :return:
    """
    n_bytes = -(-length // 8)  # round up by upside down floor division
    return bytearray(urandom(n_bytes))


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
        assert decrypted_crc == computed_crc
    except AssertionError:
        return "[ERROR] MAC ERROR. Invalid Frame (possibly corrupted). Cause : crc32 invalidation."

    # print("Frame is valid.")
    return cleartext_msg


def inject(m1, m2, m2f, verbose=False):
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

    :param verbose:
    :param m1:
    :param m2:
    :param m2f:
    :return:
    """

    k = "Key"
    b_k = bytearray()
    b_k.extend(k.encode())
    debug(verbose, "new Valid Frame : " + str(m2f.is_valid(b_k)))

    debug(verbose, "===> Computing CRC of injected message")
    m1_crc = crc32(m1)[1]
    m1_crc_ex = rc4_extended_crc32(m1)
    debug(verbose, "m1 : " + str(byte_to_list(m1)) + " " + str(m1) + " " + str(len(m1)))
    debug(verbose, "m1_crc : " + str(byte_to_list(m1_crc)) + " " + str(m1_crc) + " " + str(len(m1_crc)))
    debug(verbose, "m1_crc_ex : " + str(byte_to_list(m1_crc_ex)) + " " + str(m1_crc_ex) + " " + str(len(m1_crc_ex)))

    debug(verbose, "===> Computing CRC of encrypted message")
    m2_crc = crc32(m2)[1]
    m2_crc_ex = rc4_extended_crc32(m2)
    debug(verbose, "m2 : " + str(byte_to_list(m2)) + " " + str(m2) + " " + str(len(m2)))
    debug(verbose, "m2_crc : " + str(byte_to_list(m2_crc)) + " " + str(m2_crc) + " " + str(len(m2_crc)))
    debug(verbose, "m2_crc_ex : " + str(byte_to_list(m2_crc_ex)) + " " + str(m2_crc_ex) + " " + str(len(m2_crc_ex)))

    """
    crc_xor = bytearray()
    for x in range(len(m1_crc)):
        crc_xor.extend((m1_crc[x] ^ m2_crc[x]).to_bytes(1, byteorder='big'))
    debug(verbose, "crc_xor : " + str(byte_to_list(crc_xor)) + " " + str(crc_xor) + " " + str(len(crc_xor)))
    """

    debug(verbose, "===> Assembling messages")
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
    debug(verbose, "mpm_crc : " + str(byte_to_list(mpm_crc)) + " " + str(mpm_crc) + " " + str(len(mpm_crc)))

    mxm_crc = crc32(mxm)[1]
    mxm_crc_ex = rc4_extended_crc32(mxm)
    debug(verbose, "mxm : " + str(byte_to_list(mxm)) + " " + str(mxm) + " " + str(len(mxm)))
    debug(verbose, "mxm_crc : " + str(byte_to_list(mxm_crc)) + " " + str(mxm_crc) + " " + str(len(mxm_crc)))
    debug(verbose,
          "mxm_crc_ex : " + str(byte_to_list(mxm_crc_ex)) + " " + str(mxm_crc_ex) + " " + str(len(mxm_crc_ex)))

    debug(verbose, "===> Computing injection crc")
    charge = bytearray()
    for i in range(len(mxm_crc)):
        charge.extend((mxm_crc[i] ^ m2_crc[i]).to_bytes(1, byteorder='big'))
    debug(verbose, "charge : " + str(byte_to_list(charge)) + " " + str(charge) + " " + str(len(charge)))

    """
    debug(verbose, "computing charge 2...")
    charge2 = bytearray()
    for i in range(len(mxm_crc)):
        c = m1_crc[i] ^ m2_crc[i]
        charge2.extend((c ^ m2_crc[i]).to_bytes(1, byteorder='big'))
    debug(verbose, "charge2 : " + str(byte_to_list(charge2)) + " " + str(charge2) + " " + str(len(charge2)))
    """

    debug(verbose, "===> Getting encryption stream")
    stream = bytearray()
    for l in range(len(m2_crc_ex)):
        x = bytearray((m2_crc_ex[l] ^ m2f.payload[l]).to_bytes(1, byteorder='big'))
        stream.extend(x)
    debug(verbose, "stream : " + str(byte_to_list(stream)) + " " + str(stream) + " " + str(len(stream)))

    debug(verbose, "===> Assembling inject and encrypt")
    payload = bytearray()
    injection = bytearray()
    injection.extend(m1)
    injection.extend(charge)
    for i in range(len(stream)):
        payload.extend((injection[i] ^ m2f.payload[i]).to_bytes(1, byteorder='big'))
    debug(verbose, "payload : " + str(byte_to_list(payload)) + " " + str(payload) + " " + str(len(payload)))
    debug(verbose, "===> Message injected")

    return Frame(m2f.iv, mxm_crc, payload)


if __name__ == '__main__':
    # Variables (You would want to play here and change the values)
    plaintext = "My cleartext"
    secret_key = "Key"

    inject_message = "is modified!"

    print("=== Test Run ===")
    print("=> Plaintext : " + plaintext)
    print("=> secret : " + secret_key)
    print("=> injection message : " + inject_message)

    print("")
    print("### Setting parameters ...")

    # Plaintext
    plain = bytearray()
    plain.extend(plaintext.encode())

    # Secret
    key = bytearray()
    key.extend(secret_key.encode())

    injection = bytearray()
    injection.extend(inject_message.encode())

    print("")
    print("### 1. Executing CRC32:=proc(M) ###")

    print("CRC32(plaintext) = " + str(crc32(plain)[0]))

    print("")
    print("### 2. Executing RC4KSA:=proc(K) ###")
    r = rc4_ksa(key)
    print("RC4KSA(key) = " + str(r))

    print("")
    print("### 3. Executing RC4PRGA:=proc(R, t) ###")
    stream = list(rc4_prga(r, len(plaintext)))
    print("RC4PRGA(R, t) = " + str(stream))

    print("")
    print("### 4. Executing RC4:=proc(M, K) ###")
    rc4 = rc4_crypt(plain, key)
    print("RC4(M, K) = " + str(byte_to_list(rc4)))

    print("")
    print("### 5. Executing RandomIV:=proc() ###")
    iv = random_iv()
    print("RandomIV() = " + str(byte_to_list(iv)))

    print("")
    print("### 6. Executing Trame:=proc(M, K) ###")
    f_iv, f_crc, f_cipher = frame = wep_make_frame(plain, key)
    print(frame)
    print("Frame Validity : " + str(frame.is_valid(key)))

    print("")
    print("### 7. Executing Decrypt:=proc(K, T) ###")
    clear = rc4_decrypt(key, frame)
    if byte_to_string(clear) == plaintext:
        print("Success !")
    else:
        print("Failed to correctly decrypt :(")
    print("Decrypted payload : " + byte_to_string(clear))

    print("")
    print("### 8. Executing Inject:=proc(K, T) ###")

    try:
        assert len(plain) == len(injection)
    except AssertionError:
        print("For now only injection messages of same length as plaintext are accepted. Injection Aborted.")
        exit(0)

    new_frame = inject(injection, plain, frame, True)
    print("New Frame :")
    print(new_frame)
    print("Frame Validity : " + str(new_frame.is_valid(key)))

    clear = rc4_decrypt(key, new_frame)
    print("decrypted : " + byte_to_string(clear))
    compare = bytearray()
    for i in range(max(len(plain), len(injection))):
        if i >= len(plain):
            compare.extend(inject[i:i + 1])
        else:
            if i >= len(injection):
                compare.extend(plain[i:i + 1])
            else:
                compare.extend((plain[i] ^ injection[i]).to_bytes(1, byteorder='big'))
    if new_frame.is_valid(key) and clear == compare:
        print("Successfull injection !")
    else:
        print("Injection failed :(")

    exit(0)
