package sessions

import "net/http"

// sessionResponseWriter wraps http.ResponseWriter, but will commit any changes
// to the session when the response is written.
//
// If an error occurs when we commit the session, we will "poison" the writer
// so that it ignores any further writes. This is to prevent partially written
// data from being sent to the client, and to ensure that we don't end up in a
// half-broken state where the server thinks that the session is committed but
// the client doesn't.
type sessionResponseWriter[T any] struct {
	http.ResponseWriter
	req      *http.Request
	mgr      *Manager[T]
	written  bool
	poisoned bool // if true, ignore all writes
}

func (srw *sessionResponseWriter[T]) Write(p []byte) (int, error) {
	if srw.poisoned {
		return len(p), nil
	}
	if !srw.written {
		cont := srw.mgr.onResponse(srw.ResponseWriter, srw.req)
		srw.written = true
		if !cont {
			srw.poisoned = true
			return len(p), nil
		}
	}
	return srw.ResponseWriter.Write(p)
}

func (srw *sessionResponseWriter[T]) WriteHeader(code int) {
	if srw.poisoned {
		return
	}
	if !srw.written {
		cont := srw.mgr.onResponse(srw.ResponseWriter, srw.req)
		srw.written = true
		if !cont {
			srw.poisoned = true
			return
		}
	}
	srw.ResponseWriter.WriteHeader(code)
}

// Unwrap allows [http.ResponseController] to access the underlying
// [http.ResponseWriter], so that clients can call methods on the original
// writer.
func (srw *sessionResponseWriter[T]) Unwrap() http.ResponseWriter {
	return srw.ResponseWriter
}
