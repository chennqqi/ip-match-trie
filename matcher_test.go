package IPMatchTrie

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

type TestCaseFind struct {
	Range string
	Label string
	In    []string
	Out   []string
}

var list = []TestCaseFind{
	{
		"1.2.5.0/24", "BJ",
		[]string{"1.2.5.0", "1.2.5.255"},
		[]string{"1.2.4.255", "1.2.6.0"},
	},
	{
		"1.2.5.1/32", "OF",
		[]string{"1.2.5.1"},
		[]string{"1.2.5.2"},
	},
	{
		"210.32.122.192/27", "HZ",
		[]string{"210.32.122.192", "210.32.122.222", "210.32.122.223"},
		[]string{"210.32.122.191", "210.32.122.224"},
	},
}

var matcher *Matcher

func TestMain(m *testing.M) {

	// initial matcher
	matcher = New()

	for _, c := range list {
		matcher.Add(c.Range, c.Label)
	}

	os.Exit(m.Run())
}

func TestFind(t *testing.T) {
	assert := assert.New(t)

	for _, c := range list {
		// test ips in range
		for _, ip := range c.In {
			label, err := matcher.Match(ip)
			if assert.Nil(err, err) {
				assert.Equal(c.Label, label, ip+" should in "+c.Range)
			}
		}

		// test ips out of range
		for _, ip := range c.Out {
			label, err := matcher.Match(ip)
			if assert.Nil(err, err) {
				assert.NotEqual(c.Label, label, ip+" should not in "+c.Range)
			}
		}
	}
}

func BenchmarkFind(b *testing.B) {
	for i := 0; i < b.N; i++ {
		matcher.Match("210.32.122.222")
	}
}
