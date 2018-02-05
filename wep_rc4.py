from os import urandom
from sys import version_info

from bitstring import Bits

from wep_rc4_chop_chop.rc4 import rc4_crypt, crc32

if version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")


class Frame:

    def __init__(self, iv, crc, payload):
        self.iv = iv
        self.crc = crc
        self.payload = payload

    def decrypt(self, key: Bits):
        """
        Given the secret key, decrypts the frames payload and returns the cleartext message.
        Raises a ValuerError if the frame is not valid, i.e. if the message is not validated by its crc32.
        :param key:
        :return:
        """
        # Prepare key for decryption
        ivk = wep_make_ivk(key, self.iv)

        # Decrypt
        decrypted_payload = rc4_crypt(self.payload, ivk)

        # Get the cleartext and the crc that were in the encrypted packet
        cleartext_msg = decrypted_payload[:-len(self.crc)]
        decrypted_crc = decrypted_payload[-len(self.crc):]

        # Compute crc32 from decrypted message
        computed_crc = crc32(cleartext_msg)

        # Check if Frame is valid by verifying crc32 fingerprints
        try:
            assert decrypted_crc == computed_crc
        except AssertionError:
            raise ValueError("MAC ERROR. Invalid Frame (possibly corrupted). Cause : crc32 invalidation.")

        return cleartext_msg

    def is_valid(self, key: Bits):
        """
        (copy) Reduced function of below "rc4_decrypt"
        Returns True or False whether the Frame is valid, i.e. its crc32 is coherent to the message transported
        :param key:
        :return: True or False
        """

        try:
            _ = self.decrypt(key)
            return True
        except ValueError as e:
            print(str(e))
            return False

    def __iter__(self):
        yield self.iv
        yield self.crc
        yield self.payload

    def __str__(self):
        return ">>> WEP Frame : Initialisation Vector : " + str(self.iv) + "\n>>> WEP Frame : CRC32 : " + str(
            self.crc) + "\n>>> WEP Frame : Encrypted payload : " + str(self.payload)


def wep_make_ivk(key: Bits, iv: Bits, order="key+iv"):
    """
    Given a key and initialisation vector, returns the concatenation of both,
    depending on the order given by order (never sure what order it is)
    Default is to append iv to key.
    :param key:
    :param iv:
    :param order:
    :return:
    """
    if order == "key+iv":
        return key + iv
    elif order == "iv+key":
        return iv + key
    else:
        raise Exception("Unhandled value for argument 'order' : " + order + ". Try 'key+iv' or 'iv+key'.")


def random_iv(length=24):
    """
    Returns a list of random bits, with default length 24.
    :param length:
    :return: Bits
    """
    n_bytes = -(-length // 8)  # round up by upside down floor division
    return Bits(urandom(n_bytes))


def wep_rc4_encrypt(m: Bits, k: Bits):
    """
    RC4 Encryption in WEP mode
    Given a message m and key k, returns the WEP implementation of the rc4 encryption of m with key k
    :type m
    :param k:
    :return:
     """

    # We want 3 random bytes, or 24 random bits
    iv = random_iv(24)

    # WEP concatenates the key with a IV to encrypt
    ivk = wep_make_ivk(k, iv)

    cipher = rc4_crypt(m, ivk)

    return iv, cipher


def wep_make_frame(m: Bits, key: Bits):
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

    # Compute the crc32 of message m
    crc = crc32(m)

    # Concatenate that crc32 to its message and encrypt with key
    iv, cipher = wep_rc4_encrypt(m + crc, key)

    return Frame(iv, crc, cipher)


def wep_inject(inject: Bits, frame):
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

    NB. : the '0' in crc(0) must be of the same length as the encrypted message, since the crc varies across its length
    =============

    What we will do here is, given a frame for message m, inject the message 'inject_message' into the encrypted message

    :param inject:
    :param frame:
    :return:
    """

    # Get message length in bytes
    reference_byte_length = (len(frame.payload) - len(frame.crc)) // 8

    # Generate an array of 0 bits
    zero_bits = Bits(reference_byte_length * b"\0")

    # xor of crcs of the message to inject and '0' array : crc(inject_message) ^ crc(0)
    inject_crc_suffix = crc32(inject) ^ crc32(zero_bits)

    # xor of initial message and inject message :  crc(inject_message ^ m)
    resulting_crc = inject_crc_suffix ^ frame.crc

    # Operate injection
    result_payload = frame.payload ^ (inject + inject_crc_suffix)

    # Return a WEP frame that should be valid
    return Frame(frame.iv, resulting_crc, result_payload)
