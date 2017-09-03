package IPMatchTrie

import (
	"errors"
	"strings"
)

const (
	IPLen = 4
	big   = 0xFFFFFF
	top   = 0x80000000
)

var (
	ErrInvalidIP   = errors.New("invalid ip address")
	ErrInvalidMask = errors.New("invalid network mask")
)

type IPByte [4]byte

type RedixNode struct {
	Left  *RedixNode
	Right *RedixNode
	Value interface{}
}

type Matcher struct {
	tree *RedixNode
}

func New() *Matcher {
	return &Matcher{&RedixNode{}}
}

func (m Matcher) Add(cidr string, value interface{}) error {
	addr, mask, err := parseCIDR(cidr)
	if err != nil {
		return err
	}
	m.tree.Insert(addr, mask, value)
	return nil
}

func (m Matcher) Match(ip string) (interface{}, error) {
	addr, err := Ip4ToInt(ip)
	if err != nil {
		return nil, err
	}
	return m.tree.Find(addr), nil
}

func (tree *RedixNode) Insert(key, mask uint32, value interface{}) {
	var bit uint32 = top
	var node, next *RedixNode

	node = tree
	next = tree

	var i int
	for ; (bit & mask) > 0; i++ {
		if key&bit > 0 {
			next = node.Right
		} else {
			next = node.Left
		}

		if next == nil {
			break
		}

		bit = bit >> 1
		node = next
	}

	if next == nil {
		for (bit & mask) > 0 {
			next = &RedixNode{}

			if (key & bit) > 0 {
				node.Right = next
			} else {
				node.Left = next
			}

			bit = bit >> 1
			node = next
		}
	}

	node.Value = value
}

func (tree *RedixNode) Find(key uint32) (value interface{}) {
	var bit uint32 = top
	node := tree

	var i int
	for ; node != nil; i++ {
		if node.Value != nil {
			value = node.Value
		}

		if (key & bit) > 0 {
			node = node.Right
		} else {
			node = node.Left
		}

		bit = bit >> 1
	}

	return
}

// parse cidr to ip and mask uint32
func parseCIDR(s string) (uint32, uint32, error) {
	i := strings.IndexByte(s, '/')
	if i < 0 {
		return 0, 0, errors.New("wrong cidr format")
	}

	addr, err := Ip4ToInt(s[:i])
	if err != nil {
		return 0, 0, err
	}

	mask, err := MaskToInt(s[i+1:])
	if err != nil {
		return 0, 0, err
	}

	return addr, mask, nil
}

// Convert ip4 string to uint32
func Ip4ToInt(ip string) (uint32, error) {
	if ip[0] == '.' || ip[len(ip)-1] == '.' {
		return 0, ErrInvalidIP
	}

	var m uint
	var seg, res uint32
	for i, c := range ip {
		if c >= '0' && c <= '9' {
			seg = 10*seg + uint32(c-'0')
		}

		if c == '.' || i == (len(ip)-1) {
			res = seg<<(8*(3-m)) + res
			seg, m = 0, m+1
		}

		if (c == '.' && ip[i-1] == '.') || seg > 0xFF {
			return 0, ErrInvalidIP
		}
	}

	if m != 4 {
		return 0, ErrInvalidIP
	}

	return res, nil
}

// Convert mask string to uint32
func MaskToInt(m string) (uint32, error) {
	if m == "" || len(m) > 2 {
		return 0, ErrInvalidMask
	}

	var s int
	for _, c := range m {
		if c >= '0' && c <= 9 {
			s = 10*s + int(c-'0')
		} else {
			return 0, ErrInvalidMask
		}
	}

	if s < 1 || s > 32 {
		return 0, ErrInvalidMask
	}

	var mask uint32
	for i := 0; i < s; i++ {
		mask = mask | uint32(1<<uint32(31-i))
	}

	return mask, nil
}
