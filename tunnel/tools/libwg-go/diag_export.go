/* SPDX-License-Identifier: Apache-2.0 */

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"golang.zx2c4.com/wireguard/android/diagnostics"
)

//export wgDiagnosticsRun
func wgDiagnosticsRun(reqJSON *C.char) *C.char {
	if reqJSON == nil {
		return C.CString(`{"error":"nil request"}`)
	}
	// Буфер выделяется malloc (C.CString), освобождается free() на стороне jni.c.
	return C.CString(diagnostics.RunDiagnostics(C.GoString(reqJSON)))
}
