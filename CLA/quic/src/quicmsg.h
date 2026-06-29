/*
	quicmsg.h:	QUICCL (draft-caini-dtn-quiccl) wire-message codec.

	Pure encode/decode of the QUICCL signalling and transfer messages.
	All fields are raw big-endian (no CBOR); every message begins with a
	one-octet Message Type.  This unit depends only on <stdint.h> /
	<stddef.h> so it can be exercised in isolation.

	Decoders return the number of octets consumed (> 0), 0 if more input
	is needed to complete the message, or -1 on a malformed message.
	Encoders return the number of octets written, or -1 if the buffer is
	too small.  Decoded variable-length fields (Node ID, extension items,
	segment data) point into the caller's input buffer; copy if retained.
									*/

#ifndef QUICMSG_H
#define QUICMSG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*	Message Type codes (draft Table 2).				*/
#define QMSG_SESS_INIT		   0x01
#define QMSG_XFER_SEGMENT	   0x02
#define QMSG_XFER_ACK		   0x03
#define QMSG_XFER_REFUSE	   0x04
#define QMSG_KEEPALIVE		   0x05
#define QMSG_SESS_TERM		   0x06
#define QMSG_MSG_REJECT		   0x07

/*	XFER_SEGMENT / XFER_ACK message flags (draft Table 4).		*/
#define QMSG_FLAG_END		   0x01
#define QMSG_FLAG_START		   0x02

/*	Service Mode (XFER_SEGMENT).					*/
#define QMSG_SVC_RELIABLE	   0
#define QMSG_SVC_NOTIFIED	   1
#define QMSG_SVC_UNRELIABLE	   2

/*	XFER_REFUSE reason codes (draft Table 5).			*/
#define QMSG_REFUSE_UNKNOWN	   0x00
#define QMSG_REFUSE_COMPLETED	   0x01
#define QMSG_REFUSE_NO_RESOURCES   0x02
#define QMSG_REFUSE_RETRANSMIT	   0x03
#define QMSG_REFUSE_NOT_ACCEPTABLE 0x04
#define QMSG_REFUSE_EXT_FAILURE	   0x05
#define QMSG_REFUSE_SESS_TERM	   0x06

/*	MSG_REJECT reason codes.					*/
#define QMSG_REJECT_UNKNOWN	   0x00
#define QMSG_REJECT_UNSUPPORTED	   0x01
#define QMSG_REJECT_UNEXPECTED	   0x02

/*	SESS_TERM message flags / reason codes.  NB: SESS_TERM and
 *	MSG_REJECT field layouts are modelled on TCPCLv4 pending final
 *	verification against draft sections 4.10.1 / 4.11.1.		*/
#define QMSG_TERM_FLAG_REPLY	   0x01
#define QMSG_TERM_UNKNOWN	   0x00

typedef struct
{
	uint16_t       keepalive;   /* seconds; 0 disables.		*/
	uint64_t       segmentMru;  /* max XFER_SEGMENT payload.	*/
	uint64_t       datagramMru; /* max datagram payload.		*/
	uint64_t       transferMru; /* max bundle size.			*/
	const uint8_t *nodeId;	    /* URI, not NUL-terminated.		*/
	uint16_t       nodeIdLen;
	const uint8_t *sessExt;	    /* session extension items (opaque).	*/
	uint32_t       sessExtLen;
} QuicSessInit;

typedef struct
{
	uint8_t	       flags;
	uint16_t       segmentId;
	uint16_t       totalSegments;
	uint64_t       transferId;
	const uint8_t *xferExt;	      /* transfer ext items, START only.	*/
	uint32_t       xferExtLen;    /* START only.			*/
	uint64_t       segmentLength; /* data octets that follow header.*/
	uint64_t       bundleLength;
	uint8_t	       serviceMode;
} QuicXferSegment;

typedef struct
{
	uint8_t	 flags;
	uint16_t segmentId;
	uint64_t transferId;
	uint64_t ackLength;
} QuicXferAck;

typedef struct
{
	uint8_t	 reason;
	uint64_t transferId;
} QuicXferRefuse;

typedef struct
{
	uint8_t flags;
	uint8_t reason;
} QuicSessTerm;

typedef struct
{
	uint8_t reason;
	uint8_t rejectedType;
} QuicMsgReject;

/*	Return the message type (buf[0]), or -1 if len == 0.		*/
int quicMsgType(const uint8_t *buf, size_t len);

int quicMsgEncodeSessInit(uint8_t *buf, size_t cap, const QuicSessInit *m);
int quicMsgDecodeSessInit(const uint8_t *buf, size_t len, QuicSessInit *m);

/*	Encodes/decodes the XFER_SEGMENT header only (through Service
 *	Mode).  The return value is the header length; segmentLength data
 *	octets follow at that offset and are handled by the caller.	*/
int quicMsgEncodeXferSegmentHdr(uint8_t *buf, size_t cap,
		const QuicXferSegment *m);
int quicMsgDecodeXferSegmentHdr(const uint8_t *buf, size_t len,
		QuicXferSegment *m);

int quicMsgEncodeXferAck(uint8_t *buf, size_t cap, const QuicXferAck *m);
int quicMsgDecodeXferAck(const uint8_t *buf, size_t len, QuicXferAck *m);

int quicMsgEncodeXferRefuse(uint8_t *buf, size_t cap, const QuicXferRefuse *m);
int quicMsgDecodeXferRefuse(const uint8_t *buf, size_t len, QuicXferRefuse *m);

int quicMsgEncodeKeepalive(uint8_t *buf, size_t cap);

int quicMsgEncodeSessTerm(uint8_t *buf, size_t cap, const QuicSessTerm *m);
int quicMsgDecodeSessTerm(const uint8_t *buf, size_t len, QuicSessTerm *m);

int quicMsgEncodeMsgReject(uint8_t *buf, size_t cap, const QuicMsgReject *m);
int quicMsgDecodeMsgReject(const uint8_t *buf, size_t len, QuicMsgReject *m);

#ifdef __cplusplus
}
#endif

#endif /* QUICMSG_H */
