package connection

import (
	"net"
	"sync"
	"time"
)

// ClientSession identified by UDP address only
// No virtual IP tracking needed - client handles that!
type ClientSession struct {
	Addr        *net.UDPAddr
	LastSeen    time.Time
	BytesSent   uint64
	BytesRecv   uint64
	ConnectedAt time.Time
}

type Manager struct {
	// Key: "IP:Port" string (UDP address)
	sessions map[string]*ClientSession
	mu       sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*ClientSession),
	}
}

// Add or update client session (only UDP address, no virtual IP)
func (m *Manager) AddClient(addr *net.UDPAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := addr.String()

	if existing, ok := m.sessions[key]; ok {
		// Update existing session
		existing.LastSeen = time.Now()
		return
	}

	// New session
	session := &ClientSession{
		Addr:        addr,
		LastSeen:    time.Now(),
		ConnectedAt: time.Now(),
	}

	m.sessions[key] = session
}

// Get client by UDP address
func (m *Manager) GetClient(addr *net.UDPAddr) (*ClientSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[addr.String()]
	return session, exists
}

// Remove client by UDP address
func (m *Manager) RemoveClient(addr *net.UDPAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, addr.String())
}

// Update last seen timestamp
func (m *Manager) UpdateLastSeen(addr *net.UDPAddr) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[addr.String()]; exists {
		session.LastSeen = time.Now()
	}
}

// Update byte counters
func (m *Manager) AddBytesSent(addr *net.UDPAddr, bytes uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[addr.String()]; exists {
		session.BytesSent += bytes
	}
}

func (m *Manager) AddBytesRecv(addr *net.UDPAddr, bytes uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[addr.String()]; exists {
		session.BytesRecv += bytes
	}
}

// Remove stale sessions (no packets for timeout duration)
func (m *Manager) CleanupStale(timeout time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	removed := 0
	now := time.Now()

	for key, session := range m.sessions {
		if now.Sub(session.LastSeen) > timeout {
			delete(m.sessions, key)
			removed++
		}
	}

	return removed
}

// Get all active sessions
func (m *Manager) GetAllSessions() []*ClientSession {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*ClientSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessionCopy := *s
		sessions = append(sessions, &sessionCopy)
	}
	return sessions
}

// Count active sessions
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// Check if client exists
func (m *Manager) Exists(addr *net.UDPAddr) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.sessions[addr.String()]
	return exists
}

// Get session info for monitoring/stats
func (m *Manager) GetSessionInfo(addr *net.UDPAddr) map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[addr.String()]
	if !exists {
		return nil
	}

	return map[string]interface{}{
		"address":      session.Addr.String(),
		"connected_at": session.ConnectedAt,
		"last_seen":    session.LastSeen,
		"bytes_sent":   session.BytesSent,
		"bytes_recv":   session.BytesRecv,
		"duration":     time.Since(session.ConnectedAt).Seconds(),
	}
}
