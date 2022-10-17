package mysql

import (
	"reflect"
	"testing"
)

func TestParsePrivileges(t *testing.T) {
	got := parsePrivileges("SELECT, UPDATE, DELETE")
	want := []string{"SELECT", "UPDATE", "DELETE"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePrivilegesWithoutSpaces(t *testing.T) {
	got := parsePrivileges("SELECT,UPDATE,DELETE")
	want := []string{"SELECT", "UPDATE", "DELETE"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePrivilegesWithColumnGrants(t *testing.T) {
	got := parsePrivileges("SELECT (id, user),UPDATE, DELETE")
	want := []string{"SELECT (id, user)", "UPDATE", "DELETE"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePrivilegesWithColumnGrantsSorting(t *testing.T) {
	got := parsePrivileges("SELECT (user, id), UPDATE, DELETE")
	want := []string{"SELECT (id, user)", "UPDATE", "DELETE"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
