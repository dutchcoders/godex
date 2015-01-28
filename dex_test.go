package godex

import (
	"testing"
)

type testSet struct {
	name string
	got  []byte
	want uint32
}

var tests = []testSet{
	testSet{
		name: "test.php",
		got:  []byte{0x80, 0x7f},
		want: 16256,
	},
	testSet{
		name: "test.php",
		got:  []byte{0x01},
		want: 1,
	},
	testSet{
		name: "test.php",
		got:  []byte{0x7f},
		want: 127,
	},
	testSet{
		name: "test.php",
		got:  []byte{0x00},
		want: 0,
	},
}

func TestUleb(t *testing.T) {
	for _, test := range tests {
		value, _ := uleb128(test.got)
		if value != test.want {
			t.Errorf("Test failed %d %d", value, test.want)
		}
	}
}

func TestXxx(t *testing.T) {
	dex, err := Open("malware.dex")

	if err != nil {
		t.Errorf("%s", err)
	}

	dex.Dump()

	_ = err
}
