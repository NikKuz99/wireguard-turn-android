package main

import (
	"fmt"
	"errors"
	"syscall"
	"testing"
)

// BUG-016 regression guards: protect failures must be detectable and must not
// pass silently (they used to surface later as EPERM on the first send).

func TestIsProtectFailure(t *testing.T) {
	wrapped := fmt.Errorf("%w: fd=7 tcp/1.2.3.4:19302", errProtectFailed)
	if !isProtectFailure(wrapped) {
		t.Fatal("wrapped errProtectFailed not detected")
	}
	if !isProtectFailure(errProtectFailed) {
		t.Fatal("bare errProtectFailed not detected")
	}
	if isProtectFailure(errors.New("unrelated")) {
		t.Fatal("unrelated error matched")
	}
	if isProtectFailure(nil) {
		t.Fatal("nil matched")
	}
}

func TestIsEPERM(t *testing.T) {
	if !isEPERM(syscall.EPERM) {
		t.Fatal("bare EPERM not detected")
	}
	wrapped := fmt.Errorf("write udp 1.2.3.4:1->5.6.7.8:2: %w", syscall.EPERM)
	if !isEPERM(wrapped) {
		t.Fatal("wrapped EPERM not detected")
	}
	if isEPERM(syscall.EACCES) {
		t.Fatal("EACCES matched EPERM")
	}
	// Д-3: pion заворачивает ошибки через %v и рвёт цепочку %w — isEPERM
	// намеренно распознаёт каноничную строку «operation not permitted»
	// (см. комментарий в turn-client.go). Тест раньше ожидал обратное
	// и вечно краснел на main.
	if !isEPERM(errors.New("write udp 1.2.3.4:1->5.6.7.8:2: write: operation not permitted")) {
		t.Fatal("pion string form (D-3 fallback) not detected")
	}
	if isEPERM(syscall.ECONNREFUSED) {
		t.Fatal("ECONNREFUSED matched EPERM")
	}
	if isEPERM(errors.New("read udp ...: i/o timeout")) {
		t.Fatal("timeout matched EPERM")
	}
	if isEPERM(errors.New("no errno here")) {
		t.Fatal("plain error matched")
	}
	if isEPERM(nil) {
		t.Fatal("nil matched")
	}
}
