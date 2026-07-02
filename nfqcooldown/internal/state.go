package internal

import (
	"sync"
	"time"
)

type ClientState struct {
	LastSeen time.Time
	Cooldown time.Duration
	DropCount int
}

type LastEvent struct {
	Type      string
	IP        string
	PacketID  uint32
	Cooldown  time.Duration
	Elapsed   time.Duration
	Remaining time.Duration
}

type State struct {
	mu        sync.Mutex
	clients   map[string]ClientState
	lastEvent LastEvent
	algorithm Algorithm
}

func NewState(algorithm Algorithm) *State {
	return &State{clients: make(map[string]ClientState), algorithm: algorithm}
}

func (s *State) Decide(ip string, now time.Time, packetID uint32) (allowed bool, cooldown, elapsed, remaining time.Duration, event LastEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, exists := s.clients[ip]
	if !exists {
		cd := s.algorithm.Next()
		s.clients[ip] = ClientState{LastSeen: now, Cooldown: cd}
		ev := LastEvent{Type: "ACCEPT-FIRST", IP: ip, PacketID: packetID, Cooldown: cd}
		s.lastEvent = ev
		return true, cd, 0, 0, ev
	}

	elapsed = now.Sub(st.LastSeen)
	if elapsed >= st.Cooldown {
		cd := s.algorithm.Next()
		s.clients[ip] = ClientState{LastSeen: now, Cooldown: cd, DropCount: 0}
		ev := LastEvent{Type: "ACCEPT", IP: ip, PacketID: packetID, Cooldown: cd, Elapsed: elapsed}
		s.lastEvent = ev
		return true, cd, elapsed, 0, ev
	}

	remaining = st.Cooldown - elapsed
	ev := LastEvent{Type: "INSIDE-COOLDOWN", IP: ip, PacketID: packetID, Cooldown: st.Cooldown, Elapsed: elapsed, Remaining: remaining}
	s.lastEvent = ev
	return false, st.Cooldown, elapsed, remaining, ev
}

func (s *State) MarkDelayedAccept(ip string, now time.Time, packetID uint32, waited time.Duration) (time.Duration, LastEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cd := s.algorithm.Next()
	s.clients[ip] = ClientState{LastSeen: now, Cooldown: cd}
	ev := LastEvent{Type: "ACCEPT-AFTER-DELAY", IP: ip, PacketID: packetID, Cooldown: cd, Remaining: waited}
	s.lastEvent = ev
	return cd, ev
}

func (s *State) RememberEvent(ev LastEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastEvent = ev
}

func (s *State) Cleanup(ttl time.Duration) int {
	cutoff := time.Now().Add(-ttl)
	removed := 0

	s.mu.Lock()
	defer s.mu.Unlock()

	for ip, st := range s.clients {
		if st.LastSeen.Before(cutoff) {
			delete(s.clients, ip)
			removed++
		}
	}

	return removed
}

func (s *State) Snapshot() (tracked int, ev LastEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients), s.lastEvent
}

func (s *State) Forget(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, ip)
}

func (s *State) IncDrop(ip string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.clients[ip]
	if !ok {
		return 0
	}

	st.DropCount++
	s.clients[ip] = st
	return st.DropCount
}

func (s *State) ForceAccept(ip string, now time.Time, packetID uint32) (time.Duration, LastEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cd := s.algorithm.Next()
	s.clients[ip] = ClientState{
		LastSeen:  now,
		Cooldown:  cd,
		DropCount: 0,
	}

	ev := LastEvent{
		Type:     "FORCE-ACCEPT",
		IP:       ip,
		PacketID: packetID,
		Cooldown: cd,
	}

	s.lastEvent = ev
	return cd, ev
}