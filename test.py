import dataclasses
import unittest
from main import *

RESOLVER = ("1.1.1.1", 53)
BLOCKLIST = ["google.com"]


class TestBasicMethods(unittest.TestCase):
    def setUp(self):
        self.decoded_name = "example.com"
        self.encoded_name = b"\x07example\x03com\x00"
        # example.com, pointer to location 0 (example.com)
        self.buf = b"\x07example\x03com\x00\xc0\x00"

    def test_encode_name_uncompressed(self):
        self.assertEqual(encode_name_uncompressed(self.decoded_name), self.encoded_name)

    def test_decode_name_uncompressed(self):
        self.assertEqual(decode_name_uncompressed(self.encoded_name), self.decoded_name)

    def test_decode_name(self):
        self.assertEqual(decode_name(self.buf, 12), self.decoded_name)


class TestDNSStructures(unittest.TestCase):
    def test_dns_header(self):
        header = DNSHeader(
            id=14240,
            qr=0,
            opcode=0,
            aa=0,
            tc=0,
            rd=1,
            ra=0,
            z=2,
            rcode=0,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=1,
        )
        expected = b"7\xa0\x01 \x00\x01\x00\x00\x00\x00\x00\x01"

        self.assertEqual(header.pack(), expected)

        self.assertEqual(DNSHeader.from_buffer(expected), header)

    def test_dns_question(self):
        name = "example.com"
        self.assertEqual(
            DNSQuestion(decoded_name=name, type_=1, class_=1).pack(
                encode_name_uncompressed(name)
            ),
            b"\x07example\x03com\x00\x00\x01\x00\x01",
        )

    def test_dns_answer(self):
        name = "example.com"
        self.assertEqual(
            DNSAnswer(
                decoded_name=name,
                type_=1,
                class_=1,
                ttl=60,
                rdlength=4,
                rdata=b"\x7f\x00\x00\x01",
            ).pack(encode_name_uncompressed(name)),
            b"\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x7f\x00\x00\x01",
        )


class TestDNSPackingUnpacking(unittest.TestCase):
    def setUp(self):
        # header, 2 questions, 2 answers
        self.name = "example.com"
        self.header = DNSHeader(
            id=14240,
            qr=0,
            opcode=0,
            aa=0,
            tc=0,
            rd=1,
            ra=0,
            z=2,
            rcode=0,
            qdcount=2,
            ancount=2,
            nscount=0,
            arcount=1,
        )
        question = DNSQuestion(decoded_name=self.name, type_=1, class_=1)
        self.questions = [question, dataclasses.replace(question)]  # clone question
        answer = DNSAnswer(
            decoded_name=self.name,
            type_=1,
            class_=1,
            ttl=60,
            rdlength=4,
            rdata=b"\x7f\x00\x00\x01",
        )
        self.answers = [answer, dataclasses.replace(answer)]

    def test_pack_all_uncompressed(self):
        self.assertEqual(
            pack_all_uncompressed(self.header, self.questions, self.answers),
            # No, I did not type any of this by hand
            b"7\xa0\x01 \x00\x02\x00\x02\x00\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x7f\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x7f\x00\x00\x01",
        )

    def test_pack_all_compressed(self):
        self.assertEqual(
            pack_all_compressed(self.header, self.questions, self.answers),
            # As shown above, 100 uncompressed
            # 67 bytes compressed. Savings of 33%
            b"7\xa0\x01 \x00\x02\x00\x02\x00\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x7f\x00\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x7f\x00\x00\x01",
        )

    def test_unpack_all(self):
        # Only going to test compressed, because if it works for compressed, uncompressed works (99.9%)
        header, questions, answers = unpack_all(
            b"7\xa0\x01 \x00\x02\x00\x02\x00\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x7f\x00\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x7f\x00\x00\x01"
        )
        self.assertEqual(header, self.header)
        self.assertEqual(questions, self.questions)
        self.assertEqual(answers, self.answers)


class TestDNSQuery(unittest.TestCase):
    def setUp(self):
        pass

    def test_forward_dns_query(self):
        # No tests here, because it requires the resolver
        pass

    def test_handle_dns_query(self):
        # Recieve a DNS query of one question
        one_question = pack_all_compressed(
            DNSHeader(
                id=43919,
                qr=0,
                opcode=0,
                aa=0,
                tc=0,
                rd=1,
                ra=0,
                z=2,
                rcode=0,
                qdcount=1,
                ancount=0,
                nscount=0,
                arcount=1,
            ),
            [DNSQuestion(decoded_name="example.com", type_=1, class_=1)],
        )
        two_questions = pack_all_compressed(
            DNSHeader(
                id=43919,
                qr=0,
                opcode=0,
                aa=0,
                tc=0,
                rd=1,
                ra=0,
                z=2,
                rcode=0,
                qdcount=2,
                ancount=0,
                nscount=0,
                arcount=1,
            ),
            [
                DNSQuestion(decoded_name="example.com", type_=1, class_=1),
                DNSQuestion(decoded_name="github.com", type_=1, class_=1),
            ],
        )
        self.assertEqual(
            handle_dns_query(one_question, RESOLVER, BLOCKLIST),
            b"\xab\x8f\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01",
        )
        self.assertEqual(
            handle_dns_query(two_questions, RESOLVER, BLOCKLIST),
            b"\xab\x8f\x01 \x00\x02\x00\x00\x00\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x06github\x03com\x00\x00\x01\x00\x01",
        )
        # Recieve a DNS query of two questions

    def test_handle_single_blocking_dns_query(self):
        # Recieve a DNS query
        pass

    def test_handle_multiple_blocking_dns_query(self):
        pass
