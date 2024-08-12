package main

import (
	"fmt"
	"net"
	"os"
)

type BytePacketBuffer struct {
	buf [512]byte // 512 bytes standard size for dns packets
	pos int       // current position in the buffer
}

// NewBytePacketBuffer initializes and returns a new BytePacketBuffer
func NewBytePacketBuffer() *BytePacketBuffer {
	return &BytePacketBuffer{
		buf: [512]byte{},
		pos: 0,
	}
}

// Current position within buffer
func (b *BytePacketBuffer) Pos() int {
	return b.pos
}

// Step the buffer position forward a specific number of steps
func (b *BytePacketBuffer) Step(steps int) error {
	b.pos += steps
	return nil
}

// Change the buffer position
func (b *BytePacketBuffer) Seek(pos int) error {
	b.pos = pos
	return nil
}

// Read a single byte and move the position one step forward
func (b *BytePacketBuffer) Read() (byte, error) {
	if b.pos >= 512 {
		return 0, fmt.Errorf("end of buffer")
	}
	res := b.buf[b.pos]
	b.pos += 1
	return res, nil
}

// Get a single byte, without changing the buffer position
func (b *BytePacketBuffer) Get(pos int) (byte, error) {
	if b.pos >= 512 {
		return 0, fmt.Errorf("end of buffer")
	}
	res := b.buf[pos]
	return res, nil
}

// Get a range of bytes
func (b *BytePacketBuffer) GetRange(start, len int) ([]byte, error) {
	if start+len >= 512 {
		return nil, fmt.Errorf("End of buffer")
	}
	return b.buf[start : start+len], nil
}

// Read two bytes, stepping two steps forward
func (b *BytePacketBuffer) ReadU16() (uint16, error) {
	high, err := b.Read()
	if err != nil {
		return 0, err
	}
	low, err := b.Read()
	if err != nil {
		return 0, err
	}
	return uint16(high)<<8 | uint16(low), nil
}

func (b *BytePacketBuffer) ReadU16_Query() (QueryType, error) {
	high, err := b.Read()
	if err != nil {
		return 0, err
	}
	low, err := b.Read()
	if err != nil {
		return 0, err
	}
	return QueryType(uint16(high)<<8 | uint16(low)), nil
}

// ReadU32 reads the next 4 bytes from the buffer as a uint32
func (b *BytePacketBuffer) ReadU32() (uint32, error) {
	b1, err := b.Read()
	if err != nil {
		return 0, err
	}
	b2, err := b.Read()
	if err != nil {
		return 0, err
	}
	b3, err := b.Read()
	if err != nil {
		return 0, err
	}
	b4, err := b.Read()
	if err != nil {
		return 0, err
	}
	return uint32(b1)<<24 | uint32(b2)<<16 | uint32(b3)<<8 | uint32(b4), nil
}

// ReadQName reads a DNS question name (e.g., "www.example.com") from the buffer
// It handles DNS name compression and supports pointer jumping.
func (b *BytePacketBuffer) Read_qname(outstr *string) error {
	var pos = b.Pos()
	var delim = ""
	var jumped bool
	const maxJumps = 5
	var jumpsPerformed int

	for {
		if jumpsPerformed > maxJumps {
			return fmt.Errorf("limit of %d jumps exceeded", maxJumps)
		}

		len, err := b.Get(pos)
		if err != nil {
			return err
		}
		if (len & 0xC0) == 0xC0 {
			if !jumped {
				b.Seek(pos + 2)
			}

			offset, err := b.Get(pos + 1)
			if err != nil {
				return err
			}

			pos = int(((uint16(len) ^ 0xC0) << 8) | uint16(offset))
			jumped = true
			jumpsPerformed++
			continue
		} else {
			pos++
			if len == 0 {
				break
			}
			*outstr += delim

			rangeBytes, err := b.GetRange(pos, int(len))
			if err != nil {
				return err
			}

			*outstr += string(rangeBytes)
			delim = "."
			pos += int(len)
		}
	}

	if !jumped {
		b.Seek(pos)
	}

	return nil
}

// ResultCode is an enumeration representing DNS response codes
type ResultCode uint8

const (
	NOERROR  ResultCode = 0 // No error condition
	FORMERR  ResultCode = 1 // Format error - The name server was unable to interpret the query
	SERVFAIL ResultCode = 2 // Server failure - The name server was unable to process this query due to a problem with the name server
	NXDOMAIN ResultCode = 3 // Non-existent domain - The domain name referenced in the query does not exist
	NOTIMP   ResultCode = 4 // Not implemented - The name server does not support the requested kind of query
	REFUSED  ResultCode = 5 // Refused - The name server refuses to perform the specified operation for policy reasons
)

// String converts a ResultCode to its string representation
func (rc ResultCode) String() string {
	switch rc {
	case NOERROR:
		return "NOERROR"
	case FORMERR:
		return "FORMERR"
	case SERVFAIL:
		return "SERVFAIL"
	case NXDOMAIN:
		return "NXDOMAIN"
	case NOTIMP:
		return "NOTIMP"
	case REFUSED:
		return "REFUSED"
	default:
		return "UNKNOWN"
	}
}

// ResultCodeFromNum converts a uint8 to a ResultCode
func ResultCodeFromNum(num uint8) ResultCode {
	switch num {
	case 1:
		return FORMERR
	case 2:
		return SERVFAIL
	case 3:
		return NXDOMAIN
	case 4:
		return NOTIMP
	case 5:
		return REFUSED
	default:
		return NOERROR
	}
}

// DnsHeader represents the DNS packet header
type DnsHeader struct {
	ID                   uint16     // Identifier to match requests with responses
	RecursionDesired     bool       // Recursion desired flag
	TruncatedMessage     bool       // Message truncated flag
	AuthoritativeAnswer  bool       // Authoritative answer flag
	Opcode               uint8      // Operation code (e.g., query, inverse query)
	Response             bool       // Response flag (0 = query, 1 = response)
	ResCode              ResultCode // Response code (e.g., NOERROR, NXDOMAIN)
	CheckingDisabled     bool       // Checking disabled flag
	AuthedData           bool       // Authenticated data flag
	Z                    bool       // Reserved bit
	RecursionAvailable   bool       // Recursion available flag
	Questions            uint16     // Number of questions in the DNS packet
	Answers              uint16     // Number of answers in the DNS packet
	AuthoritativeEntries uint16     // Number of authority records in the DNS packet
	ResourceEntries      uint16     // Number of resource records in the DNS packet
}

// NewDnsHeader initializes and returns a new DnsHeader
func NewDnsHeader() *DnsHeader {
	return &DnsHeader{
		ID:                   0,
		RecursionDesired:     false,
		TruncatedMessage:     false,
		AuthoritativeAnswer:  false,
		Opcode:               0,
		Response:             false,
		ResCode:              NOERROR,
		CheckingDisabled:     false,
		AuthedData:           false,
		Z:                    false,
		RecursionAvailable:   false,
		Questions:            0,
		Answers:              0,
		AuthoritativeEntries: 0,
		ResourceEntries:      0,
	}
}

// Read parses the DNS packet header from the buffer
func (h *DnsHeader) Read(buffer *BytePacketBuffer) error {
	var err error
	h.ID, err = buffer.ReadU16() // Read ID
	if err != nil {
		return err
	}

	flags, err := buffer.ReadU16() // Read flags and decode individual bits
	if err != nil {
		return err
	}

	h.RecursionDesired = (flags >> 8 & 1) > 0
	h.TruncatedMessage = (flags >> 9 & 1) > 0
	h.AuthoritativeAnswer = (flags >> 10 & 1) > 0
	h.Opcode = uint8((flags >> 11) & 0xF)
	h.Response = (flags >> 15 & 1) > 0

	h.ResCode = ResultCodeFromNum(uint8(flags & 0xF))
	h.CheckingDisabled = (flags >> 12 & 1) > 0
	h.AuthedData = (flags >> 13 & 1) > 0
	h.Z = (flags >> 14 & 1) > 0
	h.RecursionAvailable = (flags >> 7 & 1) > 0

	h.Questions, err = buffer.ReadU16() // Read number of questions
	if err != nil {
		return err
	}

	h.Answers, err = buffer.ReadU16() // Read number of answer records
	if err != nil {
		return err
	}

	h.AuthoritativeEntries, err = buffer.ReadU16() // Read number of authority records
	if err != nil {
		return err
	}

	h.ResourceEntries, err = buffer.ReadU16() // Read number of resource records
	if err != nil {
		return err
	}

	return nil
}

// DnsQuestion represents a DNS question in the packet
type DnsQuestion struct {
	Name   string // The domain name being queried
	Qtype  uint16 // The type of query (e.g., A, AAAA, MX)
	Qclass uint16 // The class of query (usually 1 for Internet)
}

// Read parses the DNS question from the buffer
func (q *DnsQuestion) Read(buffer *BytePacketBuffer) error {
	err := buffer.Read_qname(&q.Name) // Read the domain name
	if err != nil {
		return err
	}

	q.Qtype, err = buffer.ReadU16() // Read the query type
	if err != nil {
		return err
	}

	q.Qclass, err = buffer.ReadU16() // Read the query class
	if err != nil {
		return err
	}

	return nil
}

// QueryType represents the various DNS record types
type QueryType uint16

// DNS record types
const (
	QTYPE_A     QueryType = 1  // IPv4 address
	QTYPE_NS    QueryType = 2  // Name server
	QTYPE_CNAME QueryType = 5  // Canonical name
	QTYPE_MX    QueryType = 15 // Mail exchange
	QTYPE_AAAA  QueryType = 28 // IPv6 address
)

// DnsRecord represents a DNS record (answer, authority, or additional)
type DnsRecord struct {
	Name     string    // The domain name associated with the record
	Qtype    QueryType // The type of record
	Class    uint16    // The class of record (usually 1 for Internet)
	TTL      uint32    // Time to live (in seconds) for caching
	DataLen  uint16    // The length of the record data
	Addr     net.IP    // The IP address for A and AAAA records
	Host     string    // The host name for CNAME and MX records
	Priority uint16    // The priority for MX records
}

// DnsRecordRead parses a DNS record from the buffer
func DnsRecordRead(buffer *BytePacketBuffer) (*DnsRecord, error) {
	var rec DnsRecord
	err := buffer.Read_qname(&rec.Name) // Read the domain name
	if err != nil {
		return nil, err
	}

	rec.Qtype, err = buffer.ReadU16_Query() // Read the record type
	if err != nil {
		return nil, err
	}

	rec.Class, err = buffer.ReadU16() // Read the class of the record
	if err != nil {
		return nil, err
	}

	rec.TTL, err = buffer.ReadU32() // Read the time to live (TTL)
	if err != nil {
		return nil, err
	}

	rec.DataLen, err = buffer.ReadU16() // Read the length of the record data
	if err != nil {
		return nil, err
	}

	// Parse the record based on its type
	switch rec.Qtype {
	case QTYPE_A:
		var addr [4]byte
		for i := 0; i < 4; i++ {
			b, err := buffer.Read()
			if err != nil {
				return nil, err
			}
			addr[i] = b
		}
		rec.Addr = net.IPv4(addr[0], addr[1], addr[2], addr[3])

	case QTYPE_AAAA:
		var addr [16]byte
		for i := 0; i < 16; i++ {
			b, err := buffer.Read()
			if err != nil {
				return nil, err
			}
			addr[i] = b
		}
		rec.Addr = net.IP(addr[:])

	case QTYPE_CNAME:
		err := buffer.Read_qname(&rec.Host)
		if err != nil {
			return nil, err
		}

	case QTYPE_MX:
		rec.Priority, err = buffer.ReadU16()
		if err != nil {
			return nil, err
		}
		err = buffer.Read_qname(&rec.Host)
		if err != nil {
			return nil, err
		}
	}

	return &rec, nil
}

func main() {
	// Example usage: reading a DNS response from a binary file
	data, err := os.ReadFile("response_packet.txt")
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		os.Exit(1)
	}

	// Initialize a new buffer and copy the file data into it
	buffer := NewBytePacketBuffer()
	copy(buffer.buf[:], data)

	// Parse the DNS header
	header := NewDnsHeader()
	err = header.Read(buffer)
	if err != nil {
		fmt.Printf("Failed to read DNS header: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("DNS Header: %+v\n", header)

	// Parse each DNS question
	for i := 0; i < int(header.Questions); i++ {
		var question DnsQuestion
		err = question.Read(buffer)
		if err != nil {
			fmt.Printf("Failed to read DNS question: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("DNS Question: %+v\n", question)
	}

	// Parse each DNS record in the answers section
	for i := 0; i < int(header.Answers); i++ {
		record, err := DnsRecordRead(buffer)
		if err != nil {
			fmt.Printf("Failed to read DNS record: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("DNS Record: %+v\n", record)
	}
}
