package telnetlib

import "testing"

// MakeServerType is the detection brain: it decides whether a banner means a
// username+password login, a password-only login, or an already-open shell.
// These cases all short-circuit before the conn-dependent isLoginSucceed
// fallback, so they run without a real connection.
func TestMakeServerType(t *testing.T) {
	cases := []struct {
		name   string
		banner string
		want   int
	}{
		{"username prompt", "Welcome\r\nlogin: ", UsernameAndPassword},
		{"chinese username prompt", "欢迎\r\n用户名：", UsernameAndPassword},
		{"account prompt", "Account: ", UsernameAndPassword},
		{"password only", "Password: ", OnlyPassword},
		{"busybox shell", "/ # ", UnauthorizedAccess},
		{"router shell", "<Huawei>", UnauthorizedAccess},
		{"root shell", "# ", UnauthorizedAccess},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{}
			c.lastResponse = tc.banner
			if got := c.MakeServerType(); got != tc.want {
				t.Errorf("MakeServerType(%q) = %d, want %d", tc.banner, got, tc.want)
			}
		})
	}
}

func TestIsLoginFailed(t *testing.T) {
	c := &Client{}
	failed := []string{"Login incorrect", "wrong password", "Authentication failed", "", "Password:", "Username:"}
	for _, s := range failed {
		if !c.isLoginFailed(s) {
			t.Errorf("isLoginFailed(%q) = false, want true", s)
		}
	}
	// A shell prompt is not a failure (the "$ " short-circuits isLoginSucceed,
	// so isLoginFailed must let it through).
	if c.isLoginFailed("$ ") {
		t.Error(`isLoginFailed("$ ") = true, want false`)
	}
}

func TestIsLoginSucceedPromptShortCircuits(t *testing.T) {
	c := &Client{}
	for _, s := range []string{"$ ", "# ", "<router># "} {
		if !c.isLoginSucceed(s) {
			t.Errorf("isLoginSucceed(%q) = false, want true", s)
		}
	}
}
