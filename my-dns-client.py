import sys
import random
import struct
from socket import *


#Builds query
def build_query(hostName):
    ID = random.randint(0,65535)
    FLAGS = 0x0100
    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0
    #Packing header in 6 16 bits
    HEADER = struct.pack("!HHHHHH",ID,FLAGS,QDCOUNT,ANCOUNT,NSCOUNT,ARCOUNT)
    #For debuging and comparing values to the ones stored in main
    #print("Header length:", len(HEADER))
    #print("Header hex:",HEADER.hex())
    return HEADER, ID

def hostname_encoding(hostName):
    labels = hostName.split('.')
    encoded = b''
    for label in labels:
        length = len(label)
        encoded += struct.pack("!B", length) + label.encode()
    encoded += b'\x00'
    return encoded

#Helper function to convert data from bytes into int values
def convertBytes(data):
    value = int.from_bytes(data, byteorder='big', signed= False)
    return value

def response_parsing_header(response, requestID):
    if len(response) < 12:
        return None
    
    ID = convertBytes(response[0:2])
    FLAGS = convertBytes(response[2:4])
    QDCOUNT = convertBytes(response[4:6])
    ANCOUNT = convertBytes(response[6:8])
    NSCOUNT = convertBytes(response[8:10])
    ARCOUNT = convertBytes(response[10:12])

    if ID != requestID:
        return None
    #print(ID)
    #print(FLAGS)
    #print(QDCOUNT)
    #print(ANCOUNT)
    #print(NSCOUNT)
    #print(ARCOUNT)

    QR = (FLAGS >> 15) & 1
    OPCODE = (FLAGS >> 11) & 15
    AA = (FLAGS >> 10) & 1
    TC = (FLAGS >> 9) & 1
    if TC == 1:
        print("Error: DNS response is truncated.")
        sys.exit(1)
    RD = (FLAGS >> 8) & 1
    RA = (FLAGS >> 7) & 1
    Z = (FLAGS >> 4) & 7
    RCODE = (FLAGS) & 15
    if RCODE != 0:
        print(f"Error: DNS response contains error code {RCODE}")
        sys.exit(1)
    offset = 12

    #print(f"QR:{QR}/OPCODE:{OPCODE}/AA:{AA}/TC:{TC}/RD:{RD}/RA:{RA}/Z:{Z}/RCODE:{RCODE}")
    header_dict = {"header.ID": ID, "header.FLAGS": FLAGS, "header.QDCOUNT": QDCOUNT, "header.ANCOUNT": ANCOUNT, "header.NSCOUNT": NSCOUNT, "header.ARCOUNT": ARCOUNT ,"header.QR": QR, "header.OPCODE": OPCODE, "header.AA": AA, "header.TC": TC, "header.RD": RD, "header.RA": RA, "header.Z": Z, "header.RCODE": RCODE}
    return header_dict, offset

def response_parsing_question(response, offset):
    qname = []
    while True:
        length = response[offset]
        if length == 0:
            offset += 1
            break
        offset += 1
        qname.append(response[offset:offset+length].decode())
        offset += length
    qtype, qclass = struct.unpack("!HH", response[offset:offset+4])
    offset += 4
    question_dict = {"question.QNAME": ".".join(qname), "question.QTYPE": qtype, "question.QCLASS": qclass}
    
    #print(f"QNAME:{question_dict['QNAME']}/QTYPE:{question_dict['QTYPE']}/QCLASS:{question_dict['QCLASS']}")
    return question_dict, offset

def response_parsing_answer(response, offset):
    if offset + 12 > len(response):
        return None
    name = response[offset:offset+2]
    offset += 2
    type_, class_, ttl, rdlength = struct.unpack("!HHIH", response[offset:offset+10])
    offset += 10
    rdata = response[offset:offset+rdlength]
    offset += rdlength
    answer_dict = {"answer.NAME": name, "answer.TYPE": type_, "answer.CLASS": class_, "answer.TTL": ttl, "answer.RDLENGTH": rdlength, "answer.RDATA": inet_ntoa(rdata)}
    
    #print(f"NAME:{answer_dict['NAME'].hex()}/TYPE:{answer_dict['TYPE']}/CLASS:{answer_dict['CLASS']}/TTL:{answer_dict['TTL']}/RDLENGTH:{answer_dict['RDLENGTH']}/RDATA:{answer_dict['RDATA'].hex()}")
    return answer_dict, offset

#Helper function to normalize dictionary values for output
def normalize_value(value):
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    return value
#

def main():
    serverName = '8.8.8.8'
    serverPort = 53
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    #Checks if only 2 args were passed in, if not gives error and exits
    if len(sys.argv) == 2:
        print("Preparing DNS query...")
        hostName = sys.argv[1]
        packetHeader, requestID = build_query(hostName)
        packetQuestion = hostname_encoding(hostName) + struct.pack("!HH", 1, 1)
        query = packetHeader + packetQuestion

    else:
        print("Error: my-dns-client <host-name>")
        sys.exit(1)
    #For debuging making sure values are correct

    #print("Packet Header in hex:", packetHeader.hex())
    #print("requestID:",requestID)
    #print("Packet Question in hex:", packetQuestion.hex())

    print("Contacting DNS server...")
    #Time we wait before timing out and retrying 5 seconds
    clientSocket.settimeout(5)
    #Setting response to an empty value to determine if we got a connection later
    response = None
    #Try to connect 3 times if not return error and quit
    for i in range(1,4):
        print(f"Sending DNS query..")
        print(f"DNS response received (attempt {i} of 3)")
        try:
            clientSocket.sendto(query, (serverName, serverPort))
            response, serverAddress = clientSocket.recvfrom(2048)
            #For debugging later
            #print("Response length:",len(response))
            #print("Response (HEX)", response.hex())
            break
        except timeout:
            print("Timed out waiting for DNS response.")
    clientSocket.close()

    if response is None:
        print("Error: No DNS response after 3 attempts.")
        sys.exit(1)

    print("Processing DNS response...")
    #Saved into a temp value so we can validate for errors either header was short or ID's did not match
    parsed = response_parsing_header(response,requestID)
    if parsed is None:
        print("Error occured: Response header invalid")
        sys.exit(1)  
        
    #If all went as planned save return of response_parsing_header into respective variables
    response_dic, offset = parsed
    
    # Now do it all again for question and answer
    parsed2 = response_parsing_question(response, offset) 
    if parsed2 is None:
        print("Error occured: Response question invalid")
        sys.exit(1)
    response_dic, offset = {**response_dic, **parsed2[0]}, parsed2[1]
    if response_dic.get("header.ANCOUNT") == 0:
        print("Error: DNS response contains no answers.")
        sys.exit(1)
    answers = []
    for i in range(response_dic.get("header.ANCOUNT")):
        parsed3 = response_parsing_answer(response, offset)
        if parsed3 is None:
            print("Error occured: Response answer invalid")
            sys.exit(1)
        offset = parsed3[1]
        answers.append(parsed3[0])
    
    print("----------------------------------------------------------------------------")
    for field, value in [
        (k, normalize_value(v)) for k, v in response_dic.items()
    ]:
        print(f"{field} = {value}")

    for answer in answers:
        print()
        for field, value in [
            (k, normalize_value(v)) for k, v in answer.items()
        ]:
           print(f"{field} = {value}")     

main()
