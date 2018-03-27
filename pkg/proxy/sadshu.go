package proxy

// SadashuCfg sadashu cfg
type SadashuCfg struct {
	JwtSecret       string
	JwtTokenLookup  string
	JwtAuthSchema   string
	JwtHeaderPrefix string
}
