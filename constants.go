package rawmdns

type (
	// RecordType is the type of a Resource Record; see RFC 1035
	RecordType uint16
	// RecordClass is the class of a Resource Record, e.g. "1" for INET; see RFC 1035
	RecordClass uint16
	// An OpCode is the operation being performed in a given DNS Message, usually
	// (always?) 0 i.e. "standard query" for mDNS/DNS-SD operations.
	OpCode uint8
	// A ResponseCode is the status of a response, either success/0 or some non-zero
	// code. See RFC 1035 for details.
	ResponseCode uint8
)

// recordTypes implements sort.Interface for a slice of RecordType
type recordTypes []RecordType

func (rt recordTypes) Len() int {
	return len(rt)
}
func (rt recordTypes) Less(i, j int) bool {
	return rt[i] < rt[j]
}
func (rt recordTypes) Swap(i, j int) {
	rt[i], rt[j] = rt[j], rt[i]
}

const (
	// TypeNone is not a valid type, just the zero-value for uninitialized structs.
	TypeNone RecordType = 0
	// TypeA is the typecode for an IPv4 address record. See also: RFC 1035
	TypeA RecordType = 1
	// TypeNS is the typecode for a Nameserver record. These are unused in mDNS. See also: RFC 1035
	TypeNS RecordType = 2
	// TypeCNAME is the typecode for a CNAME record, which is an alias of one name/record to another. See also: RFC 1035
	TypeCNAME RecordType = 5
	// TypeSOA is the typecode for start-of-authority record. These are unused in mDNS. See also: RFC 1035/2308
	TypeSOA RecordType = 6 // unused by mdns
	// TypeWKS is an obsolete typecode for the "Well Known Service" record type. See also: RFC 1123
	TypeWKS RecordType = 11
	// TypePTR is the typecode for a Pointer record, which is a reverse-lookup pointer mapping a string to another record. See also: RFC 1035
	TypePTR RecordType = 12
	// TypeHINFO is the typecode for a HostInfo record, which contains information about a given hosts CPU and OS. See also: RFC 1010 / 1035
	TypeHINFO RecordType = 13
	// TypeMX is the typecode for a Mail-eXchange record, which associates a DNS domain with an MTA or MTAs. See also: RFC 1035 / 7505
	TypeMX RecordType = 15
	// TypeTXT is the typecode for a TXT record, which has a special RDATA format for DNS-SD. See also: RFC 6763
	TypeTXT RecordType = 16
	// TypeRP is the typecode for a Responsible Person record, which stores information about the owner of a domain. See also: RFC 1183
	TypeRP RecordType = 17
	// TypeAFSDB is the typecode for an AFS database record. See also: RFC 1183
	TypeAFSDB RecordType = 18
	// TypeX25 is an obsolete typecode, dead along with the X.25 suite.
	TypeX25 RecordType = 19
	// TypeNSAPPTR is undocumented; this is only here to shut up the linter. Happy Googling!
	TypeNSAPPTR RecordType = 23
	// TypeSIG is the typecode for a signature record. This is used to sign/verify messages. See also: RFC 2535 / 2930 / 2931
	TypeSIG RecordType = 24
	// TypeKEY is the typecode for a key record, which complements a SIG record. See also: RFC 2535 / 2930 / 2931
	TypeKEY RecordType = 25
	// TypeAAAA is the typecode for an IPv6 address record. See also: RFC 3596
	TypeAAAA RecordType = 28
	// TypeNXT is the typecode for a NXT record, which is obsolesced by the NSEC record type. See also: RFC 4034
	TypeNXT RecordType = 30
	// TypeNIMLOC is the typecode for a "NIMROD locator" record, which is an obsolete type. See also: https://tools.ietf.org/html/draft-ietf-nimrod-dns-0
	TypeNIMLOC RecordType = 32
	// TypeSRV is the typecode for a SRV record, which is used for service discovery through DNS. See also: RFC 2052
	TypeSRV RecordType = 33
	// TypeNAPTR is the typecode for a "naming authority pointer" record. See also: RFC 3403
	TypeNAPTR RecordType = 35
	// TypeKX is the typecode for a "key exchanger" record. This is mostly, though not completely, obsolete, and is unused in DNS-SD. See also: RFC 2230
	TypeKX RecordType = 36
	// TypeCERT is the typecode for a certificate record. See also: RFC 4398
	TypeCERT RecordType = 37
	// TypeOPT is the typecode for an OPT record, which is used for various DNS extensions (aka EDNS). See also: RFC 6891
	TypeOPT RecordType = 41
	// TypeDS is the typecode for a "delegation signer" record, used for DNSSEC with delegated zones. See also: RFC 4034
	TypeDS RecordType = 43
	// TypeSSHFP is the typecode for an "SSH public key fingerprint" record. See also: RFC 4255
	TypeSSHFP RecordType = 44
	// TypeIPSECKEY is the typecode for an IPSec Key record. See also: RFC 4025
	TypeIPSECKEY RecordType = 45
	// TypeRRSIG is the typecode for a DNSSEC signature record for a secured record set. See also: RFC 4034
	TypeRRSIG RecordType = 46
	// TypeNSEC is the typecode for an authenticated denial-of-existence record. This has weaknesses versus the NSEC3 record type. See also: RFC 4034
	TypeNSEC RecordType = 47
	// TypeDNSKEY is the typecode for a DNSSEC key record. See also: RFC 4034
	TypeDNSKEY RecordType = 48
	// TypeNSEC3 is the typecode for an authenticated denial-of-existence record, with features to prevent "zone-walking" discovery attacks. See also: RFC 5155
	TypeNSEC3 RecordType = 50
	// TypeNSEC3PARAM is the typecode for a record containing parameters associated with an NSEC3 record. See also: RFC 5155
	TypeNSEC3PARAM RecordType = 51
	// TypeTLSA is the typecode for a "TLSA certificate association" record, which is used for DNS-based Authentication of Named Entities (aka DANE). See also: RFC 6698
	TypeTLSA RecordType = 52
	// TypeTKEY is the typecode for a transaction key record, which provides keying material to be used with a TSIG record. See also: RFC 2930
	TypeTKEY RecordType = 249
	// TypeTSIG is the typecode for a transaction signature record, which can be used to authenticate dynamic DNS updates. See also: RFC 2845
	TypeTSIG RecordType = 250
	// TypeIXFR is the typecode for an "incremental zone transfer" pseudo-record. It is not used by mDNS at all.
	TypeIXFR RecordType = 251
	// TypeAXFR is the typecode for an "zone transfer" pseudo-record. It is not used by mDNS at all.
	TypeAXFR RecordType = 252
	// TypeANY is special typecode used in queries asking for any/all resource-records matching a given domain name.
	TypeANY RecordType = 255
)

// ClassINET is the only DNS message class regularly used on the internet.
const ClassINET RecordClass = 1
const (
	// CodeSuccess comment only here to shut the linter up, see RFC 1035 for real information.
	CodeSuccess ResponseCode = 0
	// CodeFormatError comment only here to shut the linter up, see RFC 1035 for real information.
	CodeFormatError ResponseCode = 1
	// CodeServerFailure comment only here to shut the linter up, see RFC 1035 for real information.
	CodeServerFailure ResponseCode = 2
	// CodeNameError comment only here to shut the linter up, see RFC 1035 for real information.
	CodeNameError ResponseCode = 3
	// CodeNotImplemented comment only here to shut the linter up, see RFC 1035 for real information.
	CodeNotImplemented ResponseCode = 4
	// CodeRefused comment only here to shut the linter up, see RFC 1035 for real information.
	CodeRefused ResponseCode = 5
	// CodeYXDomain comment only here to shut the linter up, see RFC 1035 for real information.
	CodeYXDomain ResponseCode = 6
	// CodeYXRrset comment only here to shut the linter up, see RFC 1035 for real information.
	CodeYXRrset ResponseCode = 7
	// CodeNXRrset comment only here to shut the linter up, see RFC 1035 for real information.
	CodeNXRrset ResponseCode = 8
	// CodeNotAuth comment only here to shut the linter up, see RFC 1035 for real information.
	CodeNotAuth ResponseCode = 9
	// CodeNotZone comment only here to shut the linter up, see RFC 1035 for real information.
	CodeNotZone ResponseCode = 10
	// CodeBadSig comment only here to shut the linter up, see RFC 1035 for real information.
	CodeBadSig ResponseCode = 16
	// CodeBadVers comment only here to shut the linter up, see RFC 1035 for real information.
	CodeBadVers ResponseCode = 16
	// CodeBadKey comment only here to shut the linter up, see RFC 1035 for real information.
	CodeBadKey ResponseCode = 17
	// CodeBadTime comment only here to shut the linter up, see RFC 1035 for real information.
	CodeBadTime ResponseCode = 18
	// CodeBadMode comment only here to shut the linter up, see RFC 1035 for real information.
	CodeBadMode ResponseCode = 19
	// CodeBadName comment only here to shut the linter up, see RFC 1035 for real information.
	CodeBadName ResponseCode = 20
	// CodeBadAlg comment only here to shut the linter up, see RFC 1035 for real information.
	CodeBadAlg ResponseCode = 21
	// CodeBadTrunc comment only here to shut the linter up, see RFC 1035 for real information.
	CodeBadTrunc ResponseCode = 22
	// CodeBadCookie comment only here to shut the linter up, see RFC 1035 for real information.
	CodeBadCookie ResponseCode = 23
)
const (
	// OpCodeQuery comment only here to shut the linter up, see RFC 1035 for real information.
	OpCodeQuery OpCode = 0
	// OpCodeIQuery comment only here to shut the linter up, see RFC 1035 for real information.
	OpCodeIQuery OpCode = 1
	// OpCodeStatus comment only here to shut the linter up, see RFC 1035 for real information.
	OpCodeStatus OpCode = 2
	// OpCodeNotify comment only here to shut the linter up, see RFC 1035 for real information.
	OpCodeNotify OpCode = 4
	// OpCodeUpdate comment only here to shut the linter up, see RFC 1035 for real information.
	OpCodeUpdate OpCode = 5
)
