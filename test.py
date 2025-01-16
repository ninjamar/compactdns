import dataclasses
from main import *

RESOLVER = ("1.1.1.1", 53)
BLOCKLIST = ["google.com"]



def test_multiple_questions():
    

    
    questions = [DNSQuestion(decoded_name="example.com", type_=1, class_=1), DNSQuestion(decoded_name="google.com", type_=1, class_=1), DNSQuestion(decoded_name='github.com', type_=1, class_=1),]
    header = DNSHeader(id=29501, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=2, rcode=0, qdcount=len(questions), ancount=0, nscount=0, arcount=1)

    query_buf = pack_all_compressed(header, questions)  
    # print(query_buf)
    result = handle_dns_query(query_buf, RESOLVER, BLOCKLIST)

    result = unpack_all(result)


def make_test_dns_header(qdcount, ancount):
    return DNSHeader(id=14216, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=2, rcode=0, qdcount=qdcount, ancount=ancount, nscount=0, arcount=1)
if __name__ == "__main__":

    # All testing uses the following
    test_dns_header =  make_test_dns_header()

    # test_multiple_questions()
    test_decoded_name = "example.com"
    test_encoded_name = b'\x07example\x03com\x00'

    assert encode_name_uncompressed(test_decoded_name) == test_encoded_name
    assert decode_name_uncompressed(test_encoded_name) == test_decoded_name

    # Self contained
    test_dns_header =  DNSHeader(id=14216, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=2, rcode=0, qdcount=1, ancount=0, nscount=0, arcount=1)
    assert test_dns_header.pack() == b'7\x88\x01 \x00\x01\x00\x00\x00\x00\x00\x01'
    assert DNSHeader.from_buffer(b'7\x88\x01 \x00\x01\x00\x00\x00\x00\x00\x01') == test_dns_header

    test_dns_question = DNSQuestion(decoded_name=test_decoded_name, type_=1, class_=1)
    assert test_encoded_name.pack(test_encoded_name) == b'\x07example\x03com\x00\x00\x01\x00\x01'

    test_dns_answer =  DNSAnswer(decoded_name=test_decoded_name, type_=1, class_=1, ttl=60, rdlength=4, rdata=b'\x7f\x00\x00\x01')
    assert test_dns_answer.pack(test_encoded_name) == b'\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x7f\x00\x00\x01'

    assert pack_all_uncompressed()

    print(encode)