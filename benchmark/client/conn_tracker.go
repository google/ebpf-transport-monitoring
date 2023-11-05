package main

import (
//	"fmt"
	"time"
	"sync"
)

const rtt = 3000

type ConnectionMonitor struct {
	connectionId string
	callback     func()
	pendingAcks  map[string]bool
	timer        *time.Timer
	timerTask    *time.Timer
	timeoutPoint time.Time
	mu	     sync.Mutex
}

func NewConnectionMonitor(connectionId string, callback func()) *ConnectionMonitor {
	return &ConnectionMonitor{
		connectionId: connectionId,
		callback:     callback,
		pendingAcks:  make(map[string]bool),
		timer:        time.NewTimer(0),
		timerTask:    nil,
		timeoutPoint: time.Time{},
	}
}

func (m *ConnectionMonitor) AckExpected(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingAcks[id] = true
	//fmt.Println("expected", id)
	m.updateTimeoutPoint()
}

func (m *ConnectionMonitor) AckReceived(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pendingAcks, id)
	//fmt.Println("rec", id)
	m.timeoutPoint = time.Time{}
	m.updateTimeoutPoint()
}

func (m *ConnectionMonitor) DataReceived() {
	m.mu.Lock()
	defer m.mu.Unlock()
	//fmt.Println("data")
	m.timeoutPoint = time.Time{}
	m.updateTimeoutPoint()
}

func (m *ConnectionMonitor) updateTimeoutPoint() {
	numPending := len(m.pendingAcks)

	var newTimeoutPoint time.Time
	switch numPending {
	case 0:
		break
	case 1:
		newTimeoutPoint = time.Now().Add(8 * rtt * time.Microsecond)
	case 2:
		newTimeoutPoint = time.Now().Add(6 * rtt * time.Microsecond)
	default:
		newTimeoutPoint = time.Now().Add(4 * rtt * time.Microsecond)
	}

	//fmt.Println(numPending, time.Now().UnixMilli(), newTimeoutPoint.UnixMilli(), m.timeoutPoint.UnixMilli() , m.timeoutPoint.IsZero())

	if !newTimeoutPoint.IsZero() &&
		(m.timeoutPoint.IsZero() || newTimeoutPoint.Before(m.timeoutPoint)) {
		m.timeoutPoint = newTimeoutPoint
		m.updateTimer()
	}
	if newTimeoutPoint.IsZero() {
		m.updateTimer()
	}
}

func (m *ConnectionMonitor) updateTimer() {
	if m.timerTask != nil {
		m.timerTask.Stop()
		m.timerTask = nil
	}

	if !m.timeoutPoint.IsZero() {
		m.timerTask = time.AfterFunc(time.Until(m.timeoutPoint), func() {
			m.callback()
		})
	}
}
