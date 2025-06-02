package types_test

import (
	types "EnigmaNetz/Enigma-Go-Sensor/internal/processor/common"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type mockFS struct {
	existing  map[string]bool
	renameErr map[string]error
}

func (m *mockFS) Stat(name string) (os.FileInfo, error) {
	if m.existing[name] {
		return nil, nil
	}
	return nil, os.ErrNotExist
}
func (m *mockFS) Rename(oldpath, newpath string) error {
	if err, ok := m.renameErr[oldpath]; ok {
		return err
	}
	m.existing[newpath] = true
	delete(m.existing, oldpath)
	return nil
}

func TestRenameZeekLogsToXLSX(t *testing.T) {
	runDir := "/tmp"
	logFiles := []string{"conn.log", "dns.log"}
	fs := &mockFS{
		existing: map[string]bool{
			filepath.Join(runDir, "conn.log"): true,
			filepath.Join(runDir, "dns.log"):  false, // missing
		},
		renameErr: map[string]error{},
	}
	paths, err := types.RenameZeekLogsToXLSX(fs, runDir, logFiles)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exp := map[string]string{"conn.log": filepath.Join(runDir, "conn.xlsx")}
	if !reflect.DeepEqual(paths, exp) {
		t.Errorf("expected %v, got %v", exp, paths)
	}

	// Test rename error
	fs = &mockFS{
		existing:  map[string]bool{filepath.Join(runDir, "conn.log"): true},
		renameErr: map[string]error{filepath.Join(runDir, "conn.log"): errors.New("fail")},
	}
	_, err = types.RenameZeekLogsToXLSX(fs, runDir, []string{"conn.log"})
	if err == nil || err.Error() != "failed to rename conn.log to xlsx: fail" {
		t.Errorf("expected rename error, got %v", err)
	}
}
