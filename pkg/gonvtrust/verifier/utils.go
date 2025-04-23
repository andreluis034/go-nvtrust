package verify

import (
	"fmt"
)

func FormatVbiosVersion(version []byte) (strVersion string) {
	if len(version) < 6 {
		return ""
	}

	for i := 3; i >= 0; i-- {
		strVersion += fmt.Sprintf("%02x.", version[i])
	}
	strVersion += fmt.Sprintf("%02x", version[4])

	return
}
