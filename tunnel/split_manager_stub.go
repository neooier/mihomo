//go:build !linux

package tunnel

import (
	"fmt"

	C "github.com/metacubex/mihomo/constant"
)

var errSplitSkip = fmt.Errorf("split skip")

func SetSplitParentInterface(name string) {}

func ensureSplitProxy(metadata *C.Metadata) (string, error) {
	return "", fmt.Errorf("split mode is only supported on linux")
}
