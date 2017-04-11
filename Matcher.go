package IPMatchTrie

import (
	"net"
)

const (
	IP4Len  = 4
	big = 0xFFFFFF
)

type RedixNode struct {
	Left   *RedixNode
	Right  *RedixNode
	Value  interface{}
}

type Matcher struct {
	tree *RedixNode
	cache []byte
}

func New() *Matcher {
	return &Matcher{&RedixNode{}, make([]byte, IP4Len)}
}

func (m Matcher) Clone() *Matcher {
	return &Matcher{m.tree, make([]byte, IP4Len)}
}

func (m Matcher) Add(cidr string, value interface{}) error {
	ip, ipNet , err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	m.tree.Insert(nbtoi(ip.To4()), nbtoi([]byte(ipNet.Mask)), value)
	return nil
}

func (m Matcher) Match(ip string) interface{} {
	return m.tree.Find(m.ntoi(ip))
}

func (tree *RedixNode)Insert(key, mask uint32, value interface{}) {
	var bit uint32
	var node, next *RedixNode

	bit = 0x80000000
	node = tree

	for ;(bit & mask) > 0; {
		if key & bit > 0 {
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
		for ;(bit & mask) > 0; {
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

func (tree *RedixNode)Find(key uint32) (value interface{}) {
	var bit uint32

	node := tree

	bit = 0x80000000
	for ;node != nil; {
		value = node.Value

		if (key & bit) > 0 {
			node = node.Right
		} else {
			node = node.Left
		}

		bit = bit >> 1
	}

	return
}

func (m *Matcher) ntoi(s string) uint32 {
	for i := 0; i < IP4Len; i++ {
		// set cache to zero
		m.cache[i] = 0

		if len(s) == 0 {
			return 0
		}
		if i > 0 {
			if s[0] != '.' {
				return 0
			}
			s = s[1:]
		}
		n, c, ok := dtoi(s)
		if !ok || n > 0xFF {
			return 0
		}
		s = s[c:]
		m.cache[i] = byte(n)
	}

	if len(s) != 0 {
		return 0
	}

	return nbtoi(m.cache)
}

func nbtoi(ip []byte) (res uint32) {
	for i := 0; i < IP4Len ; i++ {
		res = uint32(ip[i]) << (8*(IP4Len - 1)) | res
	}
	return
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