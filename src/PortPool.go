package src

import (
	"fmt"
	"sync"
)

// PortPool manages available NAT ports for client assignment
type PortPool struct {
	minPort  int
	maxPort  int
	assigned map[int]bool
	mu       sync.Mutex
}

// NewPortPool creates a new port pool with the given range
func NewPortPool(minPort, maxPort int) *PortPool {
	return &PortPool{
		minPort:  minPort,
		maxPort:  maxPort,
		assigned: make(map[int]bool),
	}
}

// Allocate assigns a free port from the pool
func (p *PortPool) Allocate() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for port := p.minPort; port <= p.maxPort; port++ {
		if !p.assigned[port] {
			p.assigned[port] = true
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports in pool (range: %d-%d)", p.minPort, p.maxPort)
}

// Release returns a port back to the pool
func (p *PortPool) Release(port int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.assigned, port)
}

// IsAssigned checks if a port is currently assigned
func (p *PortPool) IsAssigned(port int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.assigned[port]
}

// Count returns the number of assigned ports
func (p *PortPool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.assigned)
}

// Available returns the number of available ports
func (p *PortPool) Available() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := p.maxPort - p.minPort + 1
	return total - len(p.assigned)
}
