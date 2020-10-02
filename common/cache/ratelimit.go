package cache

import (
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"go.uber.org/ratelimit"
)

type Limiter struct {
	sync.RWMutex

	rps    int
	limits map[string]ratelimit.Limiter
}

func NewLimiter(requestsPerSecond int) *Limiter {
	return &Limiter{
		rps:    requestsPerSecond,
		limits: make(map[string]ratelimit.Limiter),
	}
}

func (l *Limiter) Take(ip string) time.Time {
	var limiter ratelimit.Limiter
	var ok bool
	l.RLock()
	limiter, ok = l.limits[ip]
	l.RUnlock()
	if !ok {
		l.Lock()
		limiter = ratelimit.New(l.rps)
		l.limits[ip] = limiter
		l.Unlock()
	}
	gologger.Debugf("Taking tokens for IP %s", ip)
	return limiter.Take()
}
