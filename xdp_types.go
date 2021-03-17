package lb

type FlowKey struct {
	dstAddr [4]byte
	srcAddr [4]byte
	dstPort [2]byte
	srcPort [2]byte
	pad     uint32
}

type FlowValue struct {
	dstAddr  [4]byte
	srcAddr  [4]byte
	dstPort  [2]byte
	srcPort  [2]byte
	pad      uint32
	lastUsed uint64
}

type XdpEvent struct {
	SrcMac  [6]byte
	DstMac  [6]byte
	SrcAddr [4]byte
	SrcPort uint16
	DstAddr [4]byte
	DstPort uint16
	Message [128]byte
	Code    int32
}
