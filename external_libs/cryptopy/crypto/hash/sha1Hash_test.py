#!/usr/bin/env python
""" sha1Hash_test.py
    Unit tests for sha1.py
"""

from   crypto.hash.sha1Hash import SHA1
import unittest
import struct
assert struct.calcsize('!IIIII') == 20, '5 integers should be 20 bytes'

class SHA1_FIPS180_TestCases(unittest.TestCase):
    """ SHA-1 tests from FIPS180-1 Appendix A, B and C """

    def testFIPS180_1_Appendix_A(self):
        """ APPENDIX A.  A SAMPLE MESSAGE AND ITS MESSAGE DIGEST """
        hashAlg = SHA1()
        message        = 'abc'
        message_digest = 0xA9993E36, 0x4706816A, 0xBA3E2571, 0x7850C26C, 0x9CD0D89D
        md_string      = _toBString(message_digest)
        assert( hashAlg(message) == md_string ), 'FIPS180 Appendix A test Failed'

    def testFIPS180_1_Appendix_B(self):
        """ APPENDIX B. A SECOND SAMPLE MESSAGE AND ITS MESSAGE DIGEST """
        hashAlg = SHA1()
        message        = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
        message_digest = 0x84983E44, 0x1C3BD26E, 0xBAAE4AA1, 0xF95129E5, 0xE54670F1
        md_string      = _toBString(message_digest)
        assert( hashAlg(message) == md_string ), 'FIPS180 Appendix B test Failed'

    def testFIPS180_1_Appendix_C(self):
        """ APPENDIX C.   A THIRD SAMPLE MESSAGE AND ITS MESSAGE DIGEST
        Let the message be the binary-coded form of the ASCII string which consists
        of 1,000,000 repetitions of "a". """
        hashAlg = SHA1()
        message        = 1000000*'a'
        message_digest = 0x34AA973C, 0xD4C4DAA4, 0xF61EEB2B, 0xDBAD2731, 0x6534016F
        md_string      = _toBString(message_digest)
        assert( hashAlg(message) == md_string ), 'FIPS180 Appendix C test Failed'


def _toBlock(binaryString):
        """ Convert binary string to blocks of 5 words of uint32() """
        return [uint32(word) for word in struct.unpack('!IIIII', binaryString)]

def _toBString(block):
        """ Convert block (5 words of 32 bits to binary string """
        return ''.join([struct.pack('!I',word) for word in block])

if __name__ == '__main__':
    # Run the tests from the command line
    unittest.main()
