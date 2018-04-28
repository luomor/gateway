package proxy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/fagongzi/gateway/pkg/filter"
	"github.com/garyburd/redigo/redis"
	"github.com/valyala/fasthttp"
)

const (
	prefixJWT = "passport_jwt_"
)

var (
	errJWTMissing = errors.New("missing jwt token")
	errJWTInvalid = errors.New("invalid jwt token")
)

type tokenGetter func(filter.Context) (string, error)

// JWTCfg cfg
type JWTCfg struct {
	Secret      string `json:"secret"`
	TokenLookup string `json:"tokenLookup"`
	AuthScheme  string `json:"authScheme"`
	HeadPrefix  string `json:"headPrefix"`
	secretBytes []byte
}

// JWTFilter filter
type JWTFilter struct {
	filter.BaseFilter

	cfg         SadashuCfg
	secretBytes []byte
	getter      tokenGetter
	redisPool   *redis.Pool
}

func newSadashuJWTFilter(cfg SadashuCfg) filter.Filter {
	return &JWTFilter{
		cfg: cfg,
		redisPool: &redis.Pool{
			MaxActive:   100,
			MaxIdle:     10,
			IdleTimeout: time.Second * 60 * 10,
			Dial: func() (redis.Conn, error) {
				return redis.Dial("tcp",
					cfg.JwtRedis,
					redis.DialWriteTimeout(time.Second*10))
			},
		},
	}
}

// Init init filter
func (f *JWTFilter) Init(cfg string) error {
	// Initialize
	parts := strings.Split(f.cfg.JwtTokenLookup, ":")
	f.getter = jwtFromHeader(parts[1], f.cfg.JwtAuthSchema)
	switch parts[0] {
	case "query":
		f.getter = jwtFromQuery(parts[1])
	case "cookie":
		f.getter = jwtFromCookie(parts[1])
	}

	f.secretBytes = []byte(f.cfg.JwtSecret)
	return nil
}

// Name name
func (f *JWTFilter) Name() string {
	return FilterSadashuJWT
}

// Pre execute before proxy
func (f *JWTFilter) Pre(c filter.Context) (statusCode int, err error) {
	if strings.ToUpper(c.API().AuthFilter) != f.Name() {
		return f.BaseFilter.Pre(c)
	}

	token, err := f.getter(c)
	if err != nil {
		return fasthttp.StatusForbidden, err
	}

	claims, err := f.parseJWTToken(token)
	if err != nil {
		return fasthttp.StatusForbidden, err
	}

	if f.getJWTToken(claims) != token {
		return fasthttp.StatusForbidden, errJWTInvalid
	}

	for key, value := range claims {
		c.ForwardRequest().Header.Add(fmt.Sprintf("%s%s", f.cfg.JwtHeaderPrefix, key), fmt.Sprintf("%v", value))
	}

	return f.BaseFilter.Pre(c)
}

func (f *JWTFilter) parseJWTToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return f.secretBytes, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("error jwt token")
}

func jwtFromHeader(header string, authScheme string) tokenGetter {
	return func(c filter.Context) (string, error) {
		auth := string(c.OriginRequest().Request.Header.Peek(header))
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", errJWTMissing
	}
}

func jwtFromQuery(param string) tokenGetter {
	return func(c filter.Context) (string, error) {
		token := string(c.OriginRequest().Request.URI().QueryArgs().Peek(param))
		if token == "" {
			return "", errJWTMissing
		}
		return token, nil
	}
}

func jwtFromCookie(name string) tokenGetter {
	return func(c filter.Context) (string, error) {
		value := string(c.OriginRequest().Request.Header.Cookie(name))
		if len(value) == 0 {
			return "", errJWTMissing
		}
		return value, nil
	}
}

func (f *JWTFilter) getJWTToken(m jwt.MapClaims) string {
	conn := f.getRedis()
	value, err := redis.String(conn.Do("GET",
		f.getJWTKey(m["name"].(string),
			int(m["source"].(float64)))))
	conn.Close()

	if err != nil {
		return ""
	}

	return value
}

func (f *JWTFilter) getRedis() redis.Conn {
	return f.redisPool.Get()
}

func (f *JWTFilter) getJWTKey(name string, source int) string {
	return fmt.Sprintf("%s%s_%d", prefixJWT, name, source)
}
