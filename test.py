import dataclasses
import unittest
from main import *

RESOLVER = ("1.1.1.1", 53)
BLOCKLIST = ["google.com"]


class TestBasicMethods(unittest.TestCase):
    def setUp(self):
        self.decoded_name = "example.com"
        self.encoded_name = b'\x07example\x03com\x00'
        # example.com, pointer to location 0 (example.com)
        self.buf = b'\x07example\x03com\x00\xc0\x00'

    def test_encode_name_uncompressed(self):
        self.assertEqual(encode_name_uncompressed(self.decoded_name), self.encoded_name)
    def test_decode_name_uncompressed(self):
        self.assertEqual(decode_name_uncompressed(self.encoded_name), self.decoded_name)
    def test_decode_name(self):
        self.assertEqual(decode_name(self.buf, 12), self.decoded_name)

class TestDNSStructures(unittest.TestCase):
    def test_dns_header(self):
        header = DNSHeader(
            
        )
    def test_dns_question(self):
        pass
    def test_dns_answer(self):
        pass

class TestDNSPackingUnpacking(unittest.TestCase):
    def test_pack_all_uncompressed(self):
        pass
    def test_pack_all_compressed(self):
        pass
    def test_unpack_all(self):
        pass

class TestDNSQuery(unittest.TestCase):
    def test_forward_dns_query(self):
        pass
    def test_handle_dns_query(self):
        pass