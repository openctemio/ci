//go:build !unix

package platform

import "os"

// ownedByMe cannot check the owner here: the cache is not used.
func ownedByMe(os.FileInfo) bool { return false }

func cacheDirName() string { return "openctem-ci" }
