package flags

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/stretchr/testify/assert"
)

func TestPrepareServer(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		serverSlice    string
		expectedServer *client.Server
		expectedError  error
	}{
		{
			name:           "valid server address",
			serverSlice:    "/var/run/tracee.sock",
			expectedServer: &client.Server{Addr: "/var/run/tracee.sock"},
			expectedError:  nil,
		},
		{
			name:           "invalid server address",
			serverSlice:    "invalid/path/tracee.sock",
			expectedServer: nil,
			expectedError:  fmt.Errorf("failed to get gRPC listening address"),
		},
		{
			name:           "empty server address",
			serverSlice:    "",
			expectedServer: nil,
			expectedError:  fmt.Errorf("server address cannot be empty"),
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()

			server, err := PrepareServer(testcase.serverSlice)
			if testcase.expectedError != nil || err != nil {
				assert.ErrorContains(t, err, testcase.expectedError.Error())
			}
			assert.Equal(t, testcase.expectedServer, server)
		})
	}
}
