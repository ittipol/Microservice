package helpers

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Public function: function name starts with an uppercase letter (Can accessible from other packages)
// Private function: function name starts with an lowercase letter (Can only accessible within `models` package)

type node struct {
	startEpoch     time.Time
	lastTime       int64
	nodeId         int64
	sequence       int64
	maxNode        int64
	nodeMask       int64
	maxSequence    int64
	timestampShift uint8
	nodeIdShift    uint8
	mu             sync.Mutex
}

func NewSnowflakeGenerator(nodeId int64, customEpoch string) (*node, error) {

	var (
		// customEpoch    string = "2025-07-27 16:43:07" // Specific a starting point for timestamp
		nodeIdBits   uint8 = 10
		sequenceBits uint8 = 12
	)

	if nodeIdBits+sequenceBits > 22 {
		return nil, errors.New("nodeIdBits or sequenceBits values are invalid")
	}

	node := node{
		nodeId:         nodeId,
		maxNode:        -1 ^ (-1 << nodeIdBits),
		maxSequence:    -1 ^ (-1 << sequenceBits),
		timestampShift: nodeIdBits + sequenceBits,
		nodeIdShift:    sequenceBits,
		sequence:       0,
		lastTime:       -1,
	}

	fmt.Printf("Node: [%v/%v]\n", nodeId, node.maxNode)
	fmt.Printf("maxSequence: %v\n", node.maxSequence)
	fmt.Printf("timestampShift: %v\n", node.timestampShift)
	fmt.Printf("nodeIdShift: %v\n", node.nodeIdShift)

	node.nodeMask = node.maxNode << sequenceBits // shift 12 bit
	nodeMaskBinary := strconv.FormatInt(node.nodeMask, 2)
	fmt.Printf(":: Binary representation [%v]: %s\n", len(nodeMaskBinary), nodeMaskBinary)

	if node.nodeId < 0 || node.nodeId > node.maxNode {
		return nil, errors.New("Node number must be between 0 and " + strconv.FormatInt(node.maxNode, 10))
	}

	startEpoch, err := genTimestamp(customEpoch)
	if err != nil {
		return nil, errors.New("timestamp generating occur an error")
	}

	node.startEpoch = startEpoch

	return &node, nil
}

func (n *node) GenerateID() (int64, error) {

	n.mu.Lock()
	defer n.mu.Unlock()

	// time.Now().Sub(u) // --> t - u
	// return: now = n.startEpoch
	timestamp := time.Since(n.startEpoch).Milliseconds()

	if timestamp < n.lastTime {
		fmt.Println("invalid timestamp")
		return 0, errors.New("invalid timestamp")
	}

	if timestamp == n.lastTime {
		n.sequence = (n.sequence + 1) & n.maxSequence

		if n.sequence == 0 {
			timestamp = waitForNextTimestamp(n.startEpoch, n.lastTime)
		}
	} else {
		n.sequence = 0
	}

	n.lastTime = timestamp

	fmt.Printf(":: lastTime (time elapsed) (max lifetime 69 years): %v ms | %v sec | %v min | %v hr\n", n.lastTime, n.lastTime/1000, n.lastTime/1000/60, n.lastTime/1000/60/60)

	// explain
	// define
	// timestampShift = 10 bits + 12 bits = 22 bits
	// nodeIdShift = 12 bits

	// process
	// timestamp << int64(n.timestampShift) --> bit shift 22 bits = <timestamp_41bits>0000000000000000000000
	// n.nodeId << int64(n.nodeIdShift) --> bit shift 12 = <nodeId_10bits>000000000000
	// n.sequence = <sequence_12bits>

	// Using Bitwise OR (|) operator for merging 3 process
	// <timestamp_41bits> 0000000000 000000000000
	// 			     <nodeId_10bits> 000000000000
	//					        <sequence_12bits>

	return ((timestamp << int64(n.timestampShift)) |
		(n.nodeId << int64(n.nodeIdShift)) |
		n.sequence), nil
}

func waitForNextTimestamp(startEpoch time.Time, lastTime int64) (timestamp int64) {
	timestamp = time.Since(startEpoch).Milliseconds()

	for timestamp <= lastTime {
		timestamp = time.Since(startEpoch).Milliseconds()
	}

	return
}

func genTimestamp(timeString string) (startEpoch time.Time, err error) {

	currentTime := time.Now()

	if timeString != "" {
		var parsedTime time.Time

		layout := "2006-01-02 15:04:05"

		// parsedTime, err := time.Parse(layout, timeString)
		parsedTime, err = time.ParseInLocation(layout, timeString, time.Local)
		if err != nil {
			fmt.Println("Error parsing time:", err)
			return
		}

		currentTime = parsedTime
	}

	startEpoch = time.UnixMilli(currentTime.UnixMilli())

	fmt.Printf("starting point for timestamp (ms): %v\n", startEpoch)

	return
}
