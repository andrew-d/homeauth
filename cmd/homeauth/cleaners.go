package main

import (
	"context"
	"errors"
	"sync"
	"time"
)

// runCleaners runs all periodic background cleaning jobs for the server until
// the provided context is cancelled.
func (s *idpServer) runCleaners(ctx context.Context) {
	// Run an initial clean when the application boots up.
	if err := s.db.Write(func(d *data) error {
		now := time.Now()

		var errs []error
		for _, cf := range []cleanFunc{
			s.cleanAccessTokens,
			s.cleanOAuthCodes,
			s.cleanMagicLinks,
		} {
			if err := cf(ctx, now, d); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}); err != nil {
		s.logger.Error("error cleaning on startup", errAttr(err))
	}
	if err := s.jsonFileStore.Cleanup(); err != nil {
		s.logger.Error("error cleaning sessions on startup", errAttr(err))
	}

	const cleanInterval = 5 * time.Minute

	var wg sync.WaitGroup

	wg.Add(4)
	go s.cleanPeriodically(ctx, &wg, "oauth_codes", cleanInterval, s.cleanOAuthCodes)
	go s.cleanPeriodically(ctx, &wg, "access_tokens", cleanInterval, s.cleanAccessTokens)
	go s.cleanPeriodically(ctx, &wg, "magic_links", cleanInterval, s.cleanMagicLinks)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(cleanInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.jsonFileStore.Cleanup(); err != nil {
					s.logger.Error("error cleaning sessions", errAttr(err))
				}
			}
		}
	}()

	<-ctx.Done()
	s.logger.Info("cleaners shutting down")
	wg.Wait()
	s.logger.Info("cleaners finished")
}

type cleanFunc func(context.Context, time.Time, *data) error

func (s *idpServer) cleanPeriodically(ctx context.Context, wg *sync.WaitGroup, name string, interval time.Duration, f cleanFunc) {
	defer wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := s.db.Write(func(d *data) error {
				return f(ctx, now, d)
			}); err != nil {
				s.logger.Error("error cleaning", "name", name, errAttr(err))
			}
		}
	}
}

func (s *idpServer) cleanOAuthCodes(ctx context.Context, now time.Time, d *data) error {
	var cleaned int
	for code, oc := range d.OAuthCodes {
		if oc.Expiry.Before(now) {
			delete(d.OAuthCodes, code)
			cleaned++
		}
	}
	if cleaned > 0 {
		s.logger.Debug("cleaned expired OAuth codes", "count", cleaned)
	}
	return nil
}

func (s *idpServer) cleanAccessTokens(ctx context.Context, now time.Time, d *data) error {
	var cleaned int
	for id, at := range d.AccessTokens {
		if at.Expiry.Before(now) {
			delete(d.AccessTokens, id)
			cleaned++
		}
	}
	if cleaned > 0 {
		s.logger.Debug("cleaned expired access tokens", "count", cleaned)
	}
	return nil
}

func (s *idpServer) cleanMagicLinks(ctx context.Context, now time.Time, d *data) error {
	var cleaned int
	for token, ml := range d.MagicLinks {
		if ml.Expiry.Before(now) {
			delete(d.MagicLinks, token)
			cleaned++
		}
	}
	if cleaned > 0 {
		s.logger.Debug("cleaned expired magic links", "count", cleaned)
	}
	return nil
}
