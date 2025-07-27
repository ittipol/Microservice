package models

import (
	"sync"
	"time"
)

// Public var: var name starts with an uppercase letter (Can accessible from other packages)
// Private var: var name starts with an lowercase letter (Can only accessible within `models` package)

type Node struct {
	StartEpoch     time.Time
	LastTime       int64
	NodeId         int64
	Sequence       int64
	MaxNode        int64
	NodeMask       int64
	MaxSequence    int64
	TimestampShift uint8
	NodeIdShift    uint8
	Mu             sync.Mutex
}
