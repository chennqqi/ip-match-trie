## IPMatchTrie

Data structrue and algorithm for matching IP address against Net ranges. 

IPMatchTrie use Trie data structure, it has super fast lookup time but slow setup. It is usefull for one setup  but long time running service.

**Only IPv4 supported** 

## Usage

Create a Matcher

```
	m := IPMatchTrie.New()
```

Add ip range(CIDR) and value

```
	err := m.Add("1.2.3.0/24", "hello")

```

Find value of the ip range the ip fall into

```
 	v, err := m.Find("1.2.3.4")
``` 

 	

## License
MIT