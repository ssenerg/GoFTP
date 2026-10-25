package auth

import "time"

// TOTPCode is the code of secret for the time step, for tests.
var TOTPCode = totpCode

// AgeWrongCodes makes the wrong two-factor codes so far as old as if they
// came d earlier, for tests.
func (s *Service) AgeWrongCodes(d time.Duration) {
	s.wrongCodes.mu.Lock()
	defer s.wrongCodes.mu.Unlock()
	for _, w := range s.wrongCodes.m {
		w.last = w.last.Add(-d)
	}
}
