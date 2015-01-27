package godex

import (
	_ "bytes"
	"encoding/binary"
	"errors"
	"reflect"
)

var (
	Uleb128Pack = RegisterPack("uleb128", PackFunc(unpackUleb128))
	UintPack    = RegisterPack("uint", PackFunc(unpackUint))
	UshortPack  = RegisterPack("ushort", PackFunc(unpackUshort))
	BytePack    = RegisterPack("byte", PackFunc(unpackByteArray))
)

type Pack struct {
	fn PackFunc
}

var packs = map[string]PackFunc{}

type PackFunc func(data []byte, val reflect.Value) (uint, error)

func (d PackFunc) Unpack(data []byte, val reflect.Value) (uint, error) {
	return d(data, val)
}

func RegisterPack(name string, fn PackFunc) PackFunc {
	packs[name] = fn
	return fn
}

func unpackUleb128(data []byte, val reflect.Value) (uint, error) {
	i := uint32(0)

	value := uint32(0)
	for ; i < 5 && data[i]&0x80 == 0x80; i++ {
		value += (uint32(data[i]&0x7F) << (7 * i))
	}

	value += (uint32(data[i]) << (7 * i))
	i++

	val.SetUint(uint64(value))
	return uint(i), nil
}

func unpackUint(data []byte, val reflect.Value) (uint, error) {
	val.SetUint(uint64(binary.LittleEndian.Uint32(data[0:4])))
	return uint(4), nil
}

func unpackUshort(data []byte, val reflect.Value) (uint, error) {
	val.SetUint(uint64(binary.LittleEndian.Uint16(data[0:2])))
	return uint(2), nil
}

func unpackByteArray(data []byte, val reflect.Value) (uint, error) {
	switch val.Kind() {
	case reflect.Array:
		reflect.Copy(val, reflect.ValueOf(data[0:val.Len()]))
		return uint(val.Len()), nil
	}
	return 0, errors.New("Invalid field")
}

func Unpack(b []byte, o interface{}) (int, error) {
	offset := int(0)
	st := reflect.ValueOf(o).Elem()
	for i := 0; i < st.NumField(); i++ {
		field := st.Field(i)
		fieldType := reflect.TypeOf(o).Elem().Field(i)
		tag := fieldType.Tag.Get("pack")

		if tag == "-" {
			continue
		}

		if p, ok := packs[tag]; ok {
			length, _ := p(b[offset:], field)
			// switch (retval.(type) or field.Kind())
			offset += int(length)
			continue
		}

		err := errors.New("Not implemented type ")
		if err != nil {
			return offset, err
		}
	}

	return offset, nil
}

func _uint(b []byte) (uint64, uint32) {
	offset := 0
	val := uint64(binary.LittleEndian.Uint32(b[offset : offset+4]))
	return val, 4
}

func str(b []byte) (string, uint32) {
	i := uint32(0)
	length, offset := uleb128(b[0:])
	i += offset
	return string(b[i : i+length]), i
}

func uleb128(data []byte) (uint32, uint32) {
	i := uint32(0)

	value := uint32(0)
	for ; i < 5 && data[i]&0x80 == 0x80; i++ {
		value += (uint32(data[i]&0x7F) << (7 * i))
	}

	value += (uint32(data[i]) << (7 * i))
	i++

	return value, i
}
