// Package must provides helper functions to panic if an error is non-nil.
package must

// Do panics if err is non-nil.
func Do(err error) {
	if err != nil {
		panic(err)
	}
}

// Get panics if err is non-nil, otherwise it returns v.
func Get[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
