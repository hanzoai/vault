// Package audit provides immutable audit logging for vault operations.
package audit

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// EventType categorizes audit events.
type EventType string

const (
	EventTokenize    EventType = "tokenize"
	EventDetokenize  EventType = "detokenize"
	EventDelete      EventType = "delete"
	EventRotate      EventType = "rotate"
	EventMetadata    EventType = "metadata"
	EventKeyGenerate EventType = "key_generate"
	EventKeyRotate   EventType = "key_rotate"
	EventKeyDestroy  EventType = "key_destroy"
	EventAuthFailure EventType = "auth_failure"
)

// Event is an immutable audit record.
type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Type      EventType `json:"type"`
	Actor     string    `json:"actor"`       // service or user identity
	TenantId  string    `json:"tenantId"`
	Token     string    `json:"token,omitempty"`
	KeyID     string    `json:"keyId,omitempty"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Details   string    `json:"details,omitempty"`
}

// Logger is the audit log interface.
type Logger interface {
	Log(event Event) error
	Query(filter EventFilter) ([]Event, error)
}

// EventFilter for querying audit logs.
type EventFilter struct {
	Type     EventType
	TenantId string
	Token    string
	Actor    string
	Since    time.Time
	Until    time.Time
	Limit    int
}

// MemoryLogger is an in-memory audit logger for development/testing.
type MemoryLogger struct {
	mu     sync.Mutex
	events []Event
	seq    int
}

// NewMemoryLogger creates a new in-memory audit logger.
func NewMemoryLogger() *MemoryLogger {
	return &MemoryLogger{
		events: make([]Event, 0, 1000),
	}
}

func (l *MemoryLogger) Log(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	event.ID = fmt.Sprintf("evt_%d", l.seq)
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	l.events = append(l.events, event)
	return nil
}

func (l *MemoryLogger) Query(filter EventFilter) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var results []Event
	limit := filter.Limit
	if limit == 0 {
		limit = 100
	}

	for i := len(l.events) - 1; i >= 0 && len(results) < limit; i-- {
		e := l.events[i]
		if filter.Type != "" && e.Type != filter.Type {
			continue
		}
		if filter.TenantId != "" && e.TenantId != filter.TenantId {
			continue
		}
		if filter.Token != "" && e.Token != filter.Token {
			continue
		}
		if filter.Actor != "" && e.Actor != filter.Actor {
			continue
		}
		if !filter.Since.IsZero() && e.Timestamp.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && e.Timestamp.After(filter.Until) {
			continue
		}
		results = append(results, e)
	}

	return results, nil
}

// Len returns the number of audit events.
func (l *MemoryLogger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

// JSON serializes an event to JSON.
func (e Event) JSON() []byte {
	data, _ := json.Marshal(e)
	return data
}
