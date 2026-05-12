// Package fingerdsl compiles and evaluates the fingerprint expressions used
// in dddd's finger.yaml — a small infix language with four match operators
// (=, ==, !=, ~=), three logical operators (&&, ||, !) and parentheses.
//
// Grammar (recursive descent, left-associative):
//
//	expr     := orExpr
//	orExpr   := andExpr ("||" andExpr)*
//	andExpr  := unary  ("&&" unary)*
//	unary    := "!" unary | primary
//	primary  := match | "(" expr ")"
//	match    := IDENT OP STRING
//	OP       := "=" | "==" | "!=" | "~="
//	IDENT    := body | title | header | banner | cert | protocol | icon_hash | favicon_hash
//	STRING   := double-quoted, supports \" \\ \n \t \r escapes
package fingerdsl

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Op is a single field-match operator.
type Op int

const (
	OpContains Op = iota // =
	OpEqual              // ==
	OpNotEqual           // !=
	OpRegex              // ~=
)

func (o Op) String() string {
	switch o {
	case OpContains:
		return "="
	case OpEqual:
		return "=="
	case OpNotEqual:
		return "!="
	case OpRegex:
		return "~="
	}
	return "?"
}

// Context provides field values at evaluation time. Keys are lower-case.
// Missing fields evaluate as empty string.
type Context map[string]string

// Expression is a compiled fingerprint expression.
type Expression struct {
	root node
	src  string
}

// String returns the canonical text form (handy for debugging).
func (e *Expression) String() string { return e.root.String() }

// Eval evaluates the expression against ctx.
func (e *Expression) Eval(ctx Context) bool { return e.root.eval(ctx) }

// Parse compiles src into an Expression.
func Parse(src string) (*Expression, error) {
	p, err := newParser(src)
	if err != nil {
		return nil, err
	}
	root, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("fingerdsl: trailing tokens at pos %d (%q)", p.peek().pos, p.peek().value)
	}
	return &Expression{root: root, src: src}, nil
}

// MustParse panics on parse error — intended for tests / constants.
func MustParse(src string) *Expression {
	e, err := Parse(src)
	if err != nil {
		panic(err)
	}
	return e
}

// --- AST nodes ---------------------------------------------------------

type node interface {
	eval(Context) bool
	String() string
}

type matchNode struct {
	field string
	op    Op
	value string
	rx    *regexp.Regexp // populated for OpRegex
}

func (m *matchNode) eval(ctx Context) bool {
	got := ctx[m.field]
	switch m.op {
	case OpContains:
		return strings.Contains(strings.ToLower(got), strings.ToLower(m.value))
	case OpEqual:
		return strings.EqualFold(got, m.value)
	case OpNotEqual:
		return !strings.EqualFold(got, m.value)
	case OpRegex:
		if m.rx == nil {
			return false
		}
		return m.rx.MatchString(got)
	}
	return false
}

func (m *matchNode) String() string {
	return fmt.Sprintf("%s%s%q", m.field, m.op, m.value)
}

type andNode struct{ l, r node }

func (a *andNode) eval(c Context) bool { return a.l.eval(c) && a.r.eval(c) }
func (a *andNode) String() string      { return fmt.Sprintf("(%s && %s)", a.l, a.r) }

type orNode struct{ l, r node }

func (o *orNode) eval(c Context) bool { return o.l.eval(c) || o.r.eval(c) }
func (o *orNode) String() string      { return fmt.Sprintf("(%s || %s)", o.l, o.r) }

type notNode struct{ inner node }

func (n *notNode) eval(c Context) bool { return !n.inner.eval(c) }
func (n *notNode) String() string      { return "!" + n.inner.String() }

// --- Lexer -------------------------------------------------------------

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokString
	tokOp     // = | == | != | ~=
	tokAnd    // &&
	tokOr     // ||
	tokNot    // !  (only when not part of !=)
	tokLParen // (
	tokRParen // )
)

type token struct {
	kind  tokKind
	value string
	op    Op
	pos   int
}

type lexer struct {
	src string
	pos int
}

func (l *lexer) next() (token, error) {
	for l.pos < len(l.src) && (l.src[l.pos] == ' ' || l.src[l.pos] == '\t' || l.src[l.pos] == '\n' || l.src[l.pos] == '\r') {
		l.pos++
	}
	if l.pos >= len(l.src) {
		return token{kind: tokEOF, pos: l.pos}, nil
	}
	start := l.pos
	c := l.src[l.pos]
	switch c {
	case '(':
		l.pos++
		return token{kind: tokLParen, pos: start, value: "("}, nil
	case ')':
		l.pos++
		return token{kind: tokRParen, pos: start, value: ")"}, nil
	case '&':
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '&' {
			l.pos += 2
			return token{kind: tokAnd, pos: start, value: "&&"}, nil
		}
		return token{}, fmt.Errorf("fingerdsl: unexpected '&' at pos %d", start)
	case '|':
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '|' {
			l.pos += 2
			return token{kind: tokOr, pos: start, value: "||"}, nil
		}
		return token{}, fmt.Errorf("fingerdsl: unexpected '|' at pos %d", start)
	case '!':
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
			l.pos += 2
			return token{kind: tokOp, pos: start, value: "!=", op: OpNotEqual}, nil
		}
		l.pos++
		return token{kind: tokNot, pos: start, value: "!"}, nil
	case '=':
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
			l.pos += 2
			return token{kind: tokOp, pos: start, value: "==", op: OpEqual}, nil
		}
		l.pos++
		return token{kind: tokOp, pos: start, value: "=", op: OpContains}, nil
	case '~':
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
			l.pos += 2
			return token{kind: tokOp, pos: start, value: "~=", op: OpRegex}, nil
		}
		return token{}, fmt.Errorf("fingerdsl: unexpected '~' at pos %d", start)
	case '"':
		return l.readString()
	}
	if isIdentStart(c) {
		l.pos++
		for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
			l.pos++
		}
		return token{kind: tokIdent, pos: start, value: l.src[start:l.pos]}, nil
	}
	return token{}, fmt.Errorf("fingerdsl: unexpected %q at pos %d", c, start)
}

func (l *lexer) readString() (token, error) {
	start := l.pos
	l.pos++ // skip opening "
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '"' {
			l.pos++
			return token{kind: tokString, pos: start, value: b.String()}, nil
		}
		if c == '\\' && l.pos+1 < len(l.src) {
			nx := l.src[l.pos+1]
			switch nx {
			case '"', '\\', '/':
				b.WriteByte(nx)
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte('\\')
				b.WriteByte(nx)
			}
			l.pos += 2
			continue
		}
		b.WriteByte(c)
		l.pos++
	}
	return token{}, fmt.Errorf("fingerdsl: unterminated string starting at pos %d", start)
}

func isIdentStart(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' }
func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '.' || c == '-'
}

// --- Parser ------------------------------------------------------------

type parser struct {
	lex  lexer
	cur  token
	peek_ token
}

func newParser(src string) (*parser, error) {
	p := &parser{lex: lexer{src: src}}
	t1, err := p.lex.next()
	if err != nil {
		return nil, err
	}
	t2, err := p.lex.next()
	if err != nil {
		return nil, err
	}
	p.cur, p.peek_ = t1, t2
	return p, nil
}

func (p *parser) peek() token { return p.cur }

func (p *parser) advance() error {
	p.cur = p.peek_
	t, err := p.lex.next()
	if err != nil {
		return err
	}
	p.peek_ = t
	return nil
}

func (p *parser) parseExpr() (node, error) { return p.parseOr() }

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.cur.kind == tokOr {
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &orNode{l: left, r: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.cur.kind == tokAnd {
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &andNode{l: left, r: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (node, error) {
	if p.cur.kind == tokNot {
		if err := p.advance(); err != nil {
			return nil, err
		}
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &notNode{inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	switch p.cur.kind {
	case tokLParen:
		if err := p.advance(); err != nil {
			return nil, err
		}
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.cur.kind != tokRParen {
			return nil, fmt.Errorf("fingerdsl: expected ')' at pos %d, got %q", p.cur.pos, p.cur.value)
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		return inner, nil
	case tokIdent:
		return p.parseMatch()
	}
	return nil, fmt.Errorf("fingerdsl: unexpected token %q at pos %d", p.cur.value, p.cur.pos)
}

func (p *parser) parseMatch() (node, error) {
	field := strings.ToLower(p.cur.value)
	pos := p.cur.pos
	if err := p.advance(); err != nil {
		return nil, err
	}
	if p.cur.kind != tokOp {
		return nil, fmt.Errorf("fingerdsl: expected operator after %q at pos %d, got %q", field, pos, p.cur.value)
	}
	op := p.cur.op
	if err := p.advance(); err != nil {
		return nil, err
	}
	if p.cur.kind != tokString {
		return nil, fmt.Errorf("fingerdsl: expected string after operator at pos %d, got %q", p.cur.pos, p.cur.value)
	}
	value := p.cur.value
	if err := p.advance(); err != nil {
		return nil, err
	}
	m := &matchNode{field: field, op: op, value: value}
	if op == OpRegex {
		rx, err := regexCache.compile(value)
		if err != nil {
			return nil, fmt.Errorf("fingerdsl: invalid regex %q: %w", value, err)
		}
		m.rx = rx
	}
	return m, nil
}

// --- Regex cache -------------------------------------------------------

var regexCache = &rxCache{}

type rxCache struct {
	mu sync.RWMutex
	m  map[string]*regexp.Regexp
}

func (c *rxCache) compile(pat string) (*regexp.Regexp, error) {
	c.mu.RLock()
	if c.m != nil {
		if rx, ok := c.m[pat]; ok {
			c.mu.RUnlock()
			return rx, nil
		}
	}
	c.mu.RUnlock()
	rx, err := regexp.Compile(pat)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[string]*regexp.Regexp, 64)
	}
	c.m[pat] = rx
	c.mu.Unlock()
	return rx, nil
}

// Validate is a parse-only helper for batch linting fingerprint files.
func Validate(src string) error {
	_, err := Parse(src)
	return err
}

// ErrEmpty signals an empty expression. Useful when callers want to skip
// rather than treat as a parse error.
var ErrEmpty = errors.New("fingerdsl: empty expression")
