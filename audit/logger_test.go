package audit

import "testing"

func TestMemoryLogger(t *testing.T) {
	logger := NewMemoryLogger()

	if err := logger.Log(Event{
		Type:     EventTokenize,
		Actor:    "svc_commerce",
		TenantId: "t1",
		Token:    "tok_123",
		Success:  true,
	}); err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	if logger.Len() != 1 {
		t.Errorf("expected 1 event, got %d", logger.Len())
	}
}

func TestMemoryLoggerQuery(t *testing.T) {
	logger := NewMemoryLogger()

	logger.Log(Event{Type: EventTokenize, Actor: "svc_1", TenantId: "t1", Token: "tok_1", Success: true})
	logger.Log(Event{Type: EventDetokenize, Actor: "svc_1", TenantId: "t1", Token: "tok_1", Success: true})
	logger.Log(Event{Type: EventTokenize, Actor: "svc_2", TenantId: "t2", Token: "tok_2", Success: true})
	logger.Log(Event{Type: EventDelete, Actor: "svc_1", TenantId: "t1", Token: "tok_1", Success: true})

	// Filter by type
	events, _ := logger.Query(EventFilter{Type: EventTokenize})
	if len(events) != 2 {
		t.Errorf("expected 2 tokenize events, got %d", len(events))
	}

	// Filter by tenant
	events, _ = logger.Query(EventFilter{TenantId: "t1"})
	if len(events) != 3 {
		t.Errorf("expected 3 events for t1, got %d", len(events))
	}

	// Filter by actor
	events, _ = logger.Query(EventFilter{Actor: "svc_2"})
	if len(events) != 1 {
		t.Errorf("expected 1 event for svc_2, got %d", len(events))
	}

	// Filter by token
	events, _ = logger.Query(EventFilter{Token: "tok_1"})
	if len(events) != 3 {
		t.Errorf("expected 3 events for tok_1, got %d", len(events))
	}

	// Limit
	events, _ = logger.Query(EventFilter{Limit: 2})
	if len(events) != 2 {
		t.Errorf("expected 2 events with limit, got %d", len(events))
	}
}

func TestEventJSON(t *testing.T) {
	e := Event{
		Type:    EventTokenize,
		Actor:   "svc_1",
		Token:   "tok_1",
		Success: true,
	}

	data := e.JSON()
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestMemoryLoggerAutoID(t *testing.T) {
	logger := NewMemoryLogger()
	logger.Log(Event{Type: EventTokenize, Success: true})
	logger.Log(Event{Type: EventDetokenize, Success: true})

	events, _ := logger.Query(EventFilter{})
	if len(events) < 2 {
		t.Fatal("expected at least 2 events")
	}
	if events[0].ID == events[1].ID {
		t.Error("expected unique IDs")
	}
}
