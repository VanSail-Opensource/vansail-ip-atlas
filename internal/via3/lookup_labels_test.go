package via3

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestLookupLabelsCopyReferencedBytesAndReleaseDictionaryViews(t *testing.T) {
	// A small referenced substring of a much larger dictionary must be copied
	// into the answer, rather than retaining a whole dictionary as a string.
	dictionary := bytes.Repeat([]byte{'x'}, 1<<20)
	copy(dictionary[100:], []byte("label one"))
	copy(dictionary[200:], []byte("label two"))
	var first, second string
	var labels lookupLabels
	a, err := labels.add(dictionary[100:109], &first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := labels.add(dictionary[200:209], &second)
	if err != nil {
		t.Fatal(err)
	}
	labels.finish()
	clear(dictionary)
	if *a != "label one" || *b != "label two" {
		t.Fatal("answer labels retained mutable dictionary bytes")
	}
	*a = "caller changed this header"
	if *b != "label two" {
		t.Fatal("answer label headers alias each other")
	}
	assertNoPendingLabels(t, &labels)
	labels.finish() // Explicit and deferred completion must be idempotent.
}

func assertNoPendingLabels(t *testing.T, labels *lookupLabels) {
	t.Helper()
	if labels.count != 0 || labels.bytes != 0 || labels.spill != nil {
		t.Fatal("completed pack retained pending labels")
	}
	for _, entry := range labels.inline {
		if entry.target != nil || entry.bytes != nil {
			t.Fatal("completed pack retained a dictionary view or answer pointer")
		}
	}
}

func TestLookupLabelPackEmptyInlineAndSpillCases(t *testing.T) {
	for _, count := range []int{0, 1, 16, 17, 64, 5 + 2*PublicOrigins} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var labels lookupLabels
			values := make([]string, count)
			for i := range values {
				if _, err := labels.add([]byte(fmt.Sprintf("東京-%d", i)), &values[i]); err != nil {
					t.Fatal(err)
				}
			}
			if count == 5+2*PublicOrigins {
				if _, err := labels.add([]byte("extra"), new(string)); ErrorCode(err) != "resource_limit" {
					t.Fatal("pending label count exceeded the maximum public origin inventory")
				}
			}
			labels.finish()
			for i, value := range values {
				if value != fmt.Sprintf("東京-%d", i) {
					t.Fatal("packed UTF-8 label changed at inline/spill boundary", i)
				}
			}
			assertNoPendingLabels(t, &labels)
		})
	}
}

func TestLookupLabelPackReservesBoundsBeforeAllocation(t *testing.T) {
	var labels lookupLabels
	var value string
	if _, err := labels.add([]byte(strings.Repeat("x", 257)), &value); ErrorCode(err) != "resource_limit" {
		t.Fatal("oversized dictionary label was queued")
	}
	labels.bytes = PublicAnswerBytes
	if _, err := labels.add([]byte("x"), &value); ErrorCode(err) != "resource_limit" {
		t.Fatal("packed bytes exceeded the materialized answer limit")
	}
	if labels.count != 0 || labels.spill != nil {
		t.Fatal("rejected label allocated pending descriptors")
	}
}
