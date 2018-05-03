package proxy

// SadashuCfg sadashu cfg
type SadashuCfg struct {
	JwtTTL          int
	JwtSecret       string
	JwtTokenLookup  string
	JwtAuthSchema   string
	JwtHeaderPrefix string
	JwtRedis        string
}
