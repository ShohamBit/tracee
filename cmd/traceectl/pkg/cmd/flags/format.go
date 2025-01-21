package flags

import "fmt"

func PrepareFormat(formatFlag string) (string, error) {
	switch formatFlag {
	case "table":
		return "table", nil
	case "json":
		return "json", nil
	default:
		return "", fmt.Errorf("unsupported format type: %s", formatFlag)
	}
}
