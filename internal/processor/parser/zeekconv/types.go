package zeekconv

import (
	"time"
)

// ConnLog represents a Zeek connection log entry
type ConnLog struct {
	TS          time.Time `json:"ts"`
	UID         string    `json:"uid"`
	SrcIP       string    `json:"id.orig_h"`
	SrcPort     uint16    `json:"id.orig_p"`
	DstIP       string    `json:"id.resp_h"`
	DstPort     uint16    `json:"id.resp_p"`
	Proto       string    `json:"proto"`
	Service     string    `json:"service"`
	Duration    float64   `json:"duration"`
	OrigBytes   int64     `json:"orig_bytes"`
	RespBytes   int64     `json:"resp_bytes"`
	ConnState   string    `json:"conn_state"`
	LocalOrig   bool      `json:"local_orig"`
	LocalResp   bool      `json:"local_resp"`
	MissedBytes int64     `json:"missed_bytes"`
}

// DNSLog represents a Zeek DNS log entry
type DNSLog struct {
	TS      time.Time `json:"ts"`
	UID     string    `json:"uid"`
	SrcIP   string    `json:"id.orig_h"`
	SrcPort uint16    `json:"id.orig_p"`
	DstIP   string    `json:"id.resp_h"`
	DstPort uint16    `json:"id.resp_p"`
	Proto   string    `json:"proto"`
	TransID uint16    `json:"trans_id"`
	Query   string    `json:"query"`
	QClass  uint16    `json:"qclass"`
	QType   string    `json:"qtype"`
	Answers []string  `json:"answers"`
	TTLs    []float64 `json:"TTLs"`
	Rcode   uint16    `json:"rcode"`
	AA      bool      `json:"AA"`
	TC      bool      `json:"TC"`
	RD      bool      `json:"RD"`
	RA      bool      `json:"RA"`
}
