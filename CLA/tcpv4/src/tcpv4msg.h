/*
	tcpv4msg.h:	TCPCLv4 (RFC 9174) wire-message codec.

	Pure encode/decode of the TCPCLv4 contact header and session
	messages.  All fields are raw big-endian (no CBOR - CBOR applies to
	the bundles carried, not to the CL messages); after the contact
	header every message begins with a one-octet Message Type.  This
	unit depends only on <stdint.h> / <stddef.h> so it can be exercised
	in isolation.

	Decoders return the number of octets consumed (> 0), 0 if more input
	is needed to complete the message, or -1 on a malformed message.
	Encoders return the number of octets written, or -1 if the buffer is
	too small.  Decoded variable-length fields (Node ID, extension items)
	point into the caller's input buffer; copy if retained.
									*/

#ifndef TCPV4MSG_H
#define TCPV4MSG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*	Contact header (RFC 9174 4.2): magic "dtn!", version, flags.	*/
#define TMSG_MAGIC		  "dtn!"
#define TMSG_MAGIC_LEN		  4
#define TMSG_VERSION		  4
#define TMSG_CONTACT_LEN	  (TMSG_MAGIC_LEN + 2)

/*	Contact header flags (RFC 9174 Table 1).			*/
#define TMSG_CONTACT_CAN_TLS	  0x01

/*	Message Type codes (RFC 9174 Table 2).  Note that these differ
 *	from the QUICCL draft's codes; do not assume they match.	*/
#define TMSG_XFER_SEGMENT	  0x01
#define TMSG_XFER_ACK		  0x02
#define TMSG_XFER_REFUSE	  0x03
#define TMSG_KEEPALIVE		  0x04
#define TMSG_SESS_TERM		  0x05
#define TMSG_MSG_REJECT		  0x06
#define TMSG_SESS_INIT		  0x07

/*	XFER_SEGMENT / XFER_ACK message flags (RFC 9174 Table 5).	*/
#define TMSG_FLAG_END		  0x01
#define TMSG_FLAG_START		  0x02

/*	XFER_REFUSE reason codes (RFC 9174 Table 6).			*/
#define TMSG_REFUSE_UNKNOWN	  0x00
#define TMSG_REFUSE_COMPLETED	  0x01
#define TMSG_REFUSE_NO_RESOURCES  0x02
#define TMSG_REFUSE_RETRANSMIT	  0x03
#define TMSG_REFUSE_NOT_ACCEPTABLE 0x04
#define TMSG_REFUSE_EXT_FAILURE	  0x05
#define TMSG_REFUSE_SESS_TERM	  0x06

/*	MSG_REJECT reason codes (RFC 9174 Table 4).			*/
#define TMSG_REJECT_TYPE_UNKNOWN  0x01
#define TMSG_REJECT_UNSUPPORTED	  0x02
#define TMSG_REJECT_UNEXPECTED	  0x03

/*	SESS_TERM message flags and reason codes (RFC 9174 Tables 8, 9).	*/
#define TMSG_TERM_FLAG_REPLY	  0x01
#define TMSG_TERM_UNKNOWN	  0x00
#define TMSG_TERM_IDLE_TIMEOUT	  0x01
#define TMSG_TERM_VERSION_MISMATCH 0x02
#define TMSG_TERM_BUSY		  0x03
#define TMSG_TERM_CONTACT_FAILURE 0x04
#define TMSG_TERM_RESOURCE_EXHAUSTION 0x05

/*	Extension item flags (RFC 9174 Table 3, shared by session and
 *	transfer extension items).					*/
#define TMSG_EXT_CRITICAL	  0x01

/*	Transfer extension item types (RFC 9174 Table 7).  Transfer Length
 *	carries the total length of the transfer, which lets the receiver
 *	size its reassembly buffer once and refuse an over-large transfer
 *	at its first segment instead of part way through.		*/
#define TMSG_XFEREXT_LENGTH	  0x0001

/*	One encoded extension item: flags, type, length, value.		*/
#define TMSG_EXT_HDR_LEN	  5
#define TMSG_XFEREXT_LENGTH_LEN	  (TMSG_EXT_HDR_LEN + 8)

typedef struct
{
	uint8_t version;
	uint8_t flags;
} Tcpv4Contact;

typedef struct
{
	uint16_t       keepalive;   /* seconds; 0 disables.		*/
	uint64_t       segmentMru;  /* max XFER_SEGMENT payload.	*/
	uint64_t       transferMru; /* max bundle size.			*/
	const uint8_t *nodeId;	    /* URI, not NUL-terminated.		*/
	uint16_t       nodeIdLen;
	const uint8_t *sessExt;	    /* session extension items (opaque).	*/
	uint32_t       sessExtLen;
} Tcpv4SessInit;

typedef struct
{
	uint8_t	       flags;
	uint64_t       transferId;
	const uint8_t *xferExt;	   /* transfer ext items, START only.	*/
	uint32_t       xferExtLen; /* START only.			*/
	uint64_t       dataLength; /* data octets that follow header.	*/
} Tcpv4XferSegment;

typedef struct
{
	uint8_t	 flags;
	uint64_t transferId;
	uint64_t ackLength;
} Tcpv4XferAck;

typedef struct
{
	uint8_t	 reason;
	uint64_t transferId;
} Tcpv4XferRefuse;

typedef struct
{
	uint8_t flags;
	uint8_t reason;
} Tcpv4SessTerm;

typedef struct
{
	uint8_t reason;
	uint8_t rejectedType; /* copy of the rejected Message Header.	*/
} Tcpv4MsgReject;

/*	One extension item in its TLV container (RFC 9174 4.8 / 5.2.5).	*/
typedef struct
{
	uint8_t	       flags;
	uint16_t       type;
	uint16_t       length;
	const uint8_t *value;
} Tcpv4ExtItem;

/*	Return the message type (buf[0]), or -1 if len == 0.		*/
int tcpv4MsgType(const uint8_t *buf, size_t len);

int tcpv4MsgEncodeContact(uint8_t *buf, size_t cap, const Tcpv4Contact *m);
int tcpv4MsgDecodeContact(const uint8_t *buf, size_t len, Tcpv4Contact *m);

int tcpv4MsgEncodeSessInit(uint8_t *buf, size_t cap, const Tcpv4SessInit *m);
int tcpv4MsgDecodeSessInit(const uint8_t *buf, size_t len, Tcpv4SessInit *m);

/*	Encodes/decodes the XFER_SEGMENT header only (through Data
 *	length).  The return value is the header length; dataLength data
 *	octets follow at that offset and are handled by the caller.	*/
int tcpv4MsgEncodeXferSegmentHdr(uint8_t *buf, size_t cap,
		const Tcpv4XferSegment *m);
int tcpv4MsgDecodeXferSegmentHdr(const uint8_t *buf, size_t len,
		Tcpv4XferSegment *m);

int tcpv4MsgEncodeXferAck(uint8_t *buf, size_t cap, const Tcpv4XferAck *m);
int tcpv4MsgDecodeXferAck(const uint8_t *buf, size_t len, Tcpv4XferAck *m);

int tcpv4MsgEncodeXferRefuse(uint8_t *buf, size_t cap,
		const Tcpv4XferRefuse *m);
int tcpv4MsgDecodeXferRefuse(const uint8_t *buf, size_t len,
		Tcpv4XferRefuse *m);

int tcpv4MsgEncodeKeepalive(uint8_t *buf, size_t cap);

int tcpv4MsgEncodeSessTerm(uint8_t *buf, size_t cap, const Tcpv4SessTerm *m);
int tcpv4MsgDecodeSessTerm(const uint8_t *buf, size_t len, Tcpv4SessTerm *m);

int tcpv4MsgEncodeMsgReject(uint8_t *buf, size_t cap, const Tcpv4MsgReject *m);
int tcpv4MsgDecodeMsgReject(const uint8_t *buf, size_t len, Tcpv4MsgReject *m);

/*	Encode a Transfer Length transfer extension item (RFC 9174 5.2.5.1)
 *	into buf, for use as the xferExt of a START segment.  The item is
 *	not marked CRITICAL: a peer that does not implement it loses only
 *	the hint.  Returns the number of octets written, or -1.		*/
int tcpv4MsgEncodeXferLengthExt(uint8_t *buf, size_t cap, uint64_t length);

/*	Find the Transfer Length item in a START segment's extension list.
 *	Returns 1 and sets *length when present, 0 when absent, -1 when the
 *	list is malformed.						*/
int tcpv4MsgFindXferLength(const uint8_t *buf, size_t len, uint64_t *length);

/*	Walk an extension item list.  *off is the offset of the next item
 *	within buf and is advanced past the item that is returned.
 *	Returns 1 when an item was decoded, 0 at the end of the list, or
 *	-1 when the list disagrees with its declared length (which RFC 9174
 *	4.8 / 5.2.5 make a reception failure).				*/
int tcpv4MsgNextExtItem(const uint8_t *buf, size_t len, size_t *off,
		Tcpv4ExtItem *item);

#ifdef __cplusplus
}
#endif

#endif /* TCPV4MSG_H */
