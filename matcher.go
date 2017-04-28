package IPMatchTrie

import (
	"errors"
	"strconv"
	"strings"
)

const (
	IPLen = 4
	big   = 0xFFFFFF
	top   = 0x80000000
)

const (
	WRONG_IP   = "wrong ip address"
	WRONG_MASK = "wrong network mask"
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

func (m Matcher) Clone() *Matcher {
	return &Matcher{m.tree}
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
	addr, err := ntoi(ip)
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

	addr, err := ntoi(s[:i])
	if err != nil {
		return 0, 0, err
	}

	mask, err := mtoi(s[i+1:])
	if err != nil {
		return 0, 0, err
	}

	return addr, mask, nil
}

// convert ip string to uint32
func ntoi(s string) (uint32, error) {
	var ip [IPLen]byte
	for i := 0; i < IPLen; i++ {
		if len(s) == 0 {
			return 0, errors.New(WRONG_IP)
		}
		if i > 0 {
			if s[0] != '.' {
				return 0, errors.New(WRONG_IP)
			}
			s = s[1:]
		}
		n, c, ok := dtoi(s)
		if !ok || n > 0xFF {
			return 0, errors.New(WRONG_IP)
		}
		s = s[c:]
		ip[i] = byte(n)
	}

	if len(s) != 0 {
		return 0, errors.New(WRONG_IP)
	}

	var res uint32
	for i := 0; i < IPLen; i++ {
		res = uint32(ip[i])<<(8*(IPLen-uint32(i)-1)) | res
	}

	return res, nil
}

// Convert mask string to uint32
func mtoi(s string) (uint32, error) {
	m, err := strconv.Atoi(s)
	if err != nil || m < 1 || m > 32 {
		return 0, errors.New(WRONG_MASK)
	}

	var mask uint32
	for i := 0; i < m; i++ {
		mask = mask | uint32(1<<uint32(31-i))
	}
	return mask, nil
}

func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return big, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}
