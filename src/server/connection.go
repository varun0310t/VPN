//go:build linux
// +build linux

package server

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ClientSession identified by address and stores the DTLS connection
type ClientSession struct {
	Addr          net.Addr // Client address
	Conn          net.Conn // DTLS connection
	AssignedIP    net.IP   // Full IP address (e.g., 10.8.0.2)
	LastSeen      time.Time
	Authenticated bool
	BytesSent     uint64
	BytesRecv     uint64
	ConnectedAt   time.Time
}

type Manager struct {
	sessions    map[string]*ClientSession // Key: addr.String()
	assignedIPs map[string]*ClientSession // Key: IP string (e.g., "10.8.0.2")
	IPPool      *IPPool
	mu          sync.RWMutex
}

func NewManager() (*Manager, error) {
	return &Manager{
		sessions:    make(map[string]*ClientSession),
		assignedIPs: make(map[string]*ClientSession),
		IPPool:      NewIPPool(ServerCfg.IPPoolMin, ServerCfg.IPPoolMax),
	}, nil
}

// AddClient creates a new client session with DTLS connection
func (m *Manager) AddClient(addr net.Addr, conn net.Conn) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := addr.String()

	if existing, ok := m.sessions[key]; ok {
		existing.LastSeen = time.Now()
		existing.Conn = conn // Update connection
		return nil
	}

	// Allocate IP (returns last octet as int)
	lastOctet, err := m.IPPool.Allocate()
	if err != nil {
		return fmt.Errorf("failed to allocate IP: %w", err)
	}

	// Convert to net.IP
	assignedIP := net.IPv4(10, 8, 0, byte(lastOctet))

	session := &ClientSession{
		Addr:        addr,
		Conn:        conn,
		AssignedIP:  assignedIP,
		LastSeen:    time.Now(),
		ConnectedAt: time.Now(),
	}

	m.sessions[key] = session
	m.assignedIPs[assignedIP.String()] = session

	fmt.Printf("Client connected: %s -> Assigned IP: %s\n", addr.String(), assignedIP.String())
	return nil
}

// Get client by address
func (m *Manager) GetClient(addr net.Addr) (*ClientSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[addr.String()]
	return session, exists
}

// GetClientByIP looks up client by their assigned IP
func (m *Manager) GetClientByIP(ip net.IP) (*ClientSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.assignedIPs[ip.String()]
	return session, exists
}

// GetOrAddClient adds client if not exists and returns the session
func (m *Manager) GetOrAddClient(addr net.Addr, conn net.Conn) (*ClientSession, error) {
	key := addr.String()

	// Try read lock first (fast path)
	m.mu.RLock()
	if session, exists := m.sessions[key]; exists {
		session.LastSeen = time.Now()
		m.mu.RUnlock()
		return session, nil
	}
	m.mu.RUnlock()

	// Need to add - upgrade to write lock
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check (another goroutine might have added it)
	if session, exists := m.sessions[key]; exists {
		session.LastSeen = time.Now()
		return session, nil
	}

	// Allocate IP (returns last octet as int)
	lastOctet, err := m.IPPool.Allocate()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate IP: %w", err)
	}

	// Convert to net.IP
	assignedIP := net.IPv4(10, 8, 0, byte(lastOctet))

	// Create new session
	session := &ClientSession{
		Addr:        addr,
		Conn:        conn,
		AssignedIP:  assignedIP,
		LastSeen:    time.Now(),
		ConnectedAt: time.Now(),
	}
	m.sessions[key] = session
	m.assignedIPs[assignedIP.String()] = session

	fmt.Printf("Client connected: %s -> Assigned IP: %s\n", addr.String(), assignedIP.String())
	return session, nil
}

// GetClientConnection retrieves the DTLS connection for a client by address
func (m *Manager) GetClientConnection(addr net.Addr) (net.Conn, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[addr.String()]
	if !exists {
		return nil, false
	}
	return session.Conn, true
}

// Remove client by address
func (m *Manager) RemoveClient(addr net.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := addr.String()
	if session, exists := m.sessions[key]; exists {
		// Close the connection
		if session.Conn != nil {
			session.Conn.Close()
		}

		// Release IP (extract last octet)
		lastOctet := int(session.AssignedIP.To4()[3])
		m.IPPool.Release(lastOctet)

		delete(m.assignedIPs, session.AssignedIP.String())
		delete(m.sessions, key)

		fmt.Printf("Client disconnected: %s (Assigned IP: %s)\n", addr.String(), session.AssignedIP.String())
	}
}

// Update last seen timestamp
func (m *Manager) UpdateLastSeen(addr net.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[addr.String()]; exists {
		session.LastSeen = time.Now()
	}
}

// Update byte counters
func (m *Manager) AddBytesSent(addr net.Addr, bytes uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[addr.String()]; exists {
		session.BytesSent += bytes
	}
}

func (m *Manager) AddBytesRecv(addr net.Addr, bytes uint64) {
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
			// Close connection
			if session.Conn != nil {
				session.Conn.Close()
			}

			// Release IP (extract last octet)
			lastOctet := int(session.AssignedIP.To4()[3])
			m.IPPool.Release(lastOctet)

			delete(m.assignedIPs, session.AssignedIP.String())
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
func (m *Manager) Exists(addr net.Addr) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.sessions[addr.String()]
	return exists
}

// Get session info for monitoring/stats
func (m *Manager) GetSessionInfo(addr net.Addr) map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[addr.String()]
	if !exists {
		return nil
	}

	return map[string]interface{}{
		"address":      session.Addr.String(),
		"assigned_ip":  session.AssignedIP.String(),
		"connected_at": session.ConnectedAt,
		"last_seen":    session.LastSeen,
		"bytes_sent":   session.BytesSent,
		"bytes_recv":   session.BytesRecv,
		"duration":     time.Since(session.ConnectedAt).Seconds(),
	}
}

// SetAuthenticated marks a client session as authenticated
func (m *Manager) SetAuthenticated(addr net.Addr, authenticated bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if session, exists := m.sessions[addr.String()]; exists {
		session.Authenticated = authenticated
		if authenticated {
			fmt.Printf("Client %s authenticated successfully\n", addr.String())
		}
	}
}

// WriteToClient sends data to a specific client using their stored connection
func (m *Manager) WriteToClient(addr net.Addr, data []byte) error {
	m.mu.RLock()
	session, exists := m.sessions[addr.String()]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("client not found: %s", addr.String())
	}

	if session.Conn == nil {
		return fmt.Errorf("no connection for client: %s", addr.String())
	}

	_, err := session.Conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write to client %s: %w", addr.String(), err)
	}

	// Update bytes sent
	m.AddBytesSent(addr, uint64(len(data)))

	return nil
}
