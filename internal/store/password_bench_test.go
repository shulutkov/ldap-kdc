package store

import "testing"

func BenchmarkHashPassword(b *testing.B) {
	for b.Loop() {
		if _, err := HashPassword("a reasonably long password"); err != nil {
			b.Fatal(err)
		}
	}
}
