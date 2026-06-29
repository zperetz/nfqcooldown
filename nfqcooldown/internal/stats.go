package internal

import "sync/atomic"

type Counters struct {
	Accepted uint64
	Dropped  uint64
	Delayed  uint64
	Rejected uint64
}
func (c *Counters) IncAccepted() { atomic.AddUint64(&c.Accepted, 1) }
func (c *Counters) IncDropped() { atomic.AddUint64(&c.Dropped, 1) }
func (c *Counters) IncDelayed() { atomic.AddUint64(&c.Delayed, 1) }
func (c *Counters) IncRejected() { atomic.AddUint64(&c.Rejected, 1) }
func (c *Counters) Snapshot() (accepted, delayed, dropped, rejected uint64) {
	return atomic.LoadUint64(&c.Accepted), atomic.LoadUint64(&c.Delayed), atomic.LoadUint64(&c.Dropped), atomic.LoadUint64(&c.Rejected)
}
