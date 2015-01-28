package godex

import (
	_ "bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
)

const ENDIAN_CONSTANT = 0x12345678
const REVERSE_ENDIAN_CONSTANT = 0x78563412
const NO_INDEX = 0xffffffff

var DEX_FILE_MAGIC = []byte{0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00}

type AccessFlags uint32

const (
	ACC_PUBLIC = 1 << iota
	ACC_PRIVATE
	ACC_PROTECTED
	ACC_STATIC
	ACC_FINAL
	ACC_SYNCHRONIZED
	ACC_VOLATILE
	ACC_BRIDGE
	ACC_TRANSIENT
	ACC_VARARGS
	ACC_NATIVE
	ACC_INTERFACE
	ACC_ABSTRACT
	ACC_STRICT
	ACC_SYNTHETIC
	ACC_ANNOTATION
	ACC_ENUM
	ACC_CONSTRUCTOR           = 0x10000
	ACC_DECLARED_SYNCHRONIZED = 0x20000
)

func (af AccessFlags) String() string {
	str := ""
	if af&ACC_PUBLIC == 0 {
		str += "public "
	} else if af&ACC_PRIVATE != 0 {
		str += "private "
	} else if af&ACC_PROTECTED != 0 {
		str += "protected "
	} else if af&ACC_STATIC != 0 {
		str += "static "
	} else if af&ACC_FINAL != 0 {
		str += "final "
	} else if af&ACC_SYNCHRONIZED != 0 {
		str += "synchronized "
	} else if af&ACC_CONSTRUCTOR != 0 {
		str += "constructor "
	}
	return str

	return str
}

type Header struct {
	Magic           [8]byte  `pack:"byte"`
	Checksum        uint32   `pack:"uint"`
	Signature       [20]byte `pack:"byte"`
	FileSize        uint32   `pack:"uint"`
	HeaderSize      uint32   `pack:"uint"`
	EndianTag       uint32   `pack:"uint"`
	LinkSize        uint32   `pack:"uint"`
	LinkOff         uint32   `pack:"uint"`
	MapOff          uint32   `pack:"uint"`
	StringIdsSize   uint32   `pack:"uint"`
	StringIdsOffset uint32   `pack:"uint"`
	TypeIdsSize     uint32   `pack:"uint"`
	TypeIdsOffset   uint32   `pack:"uint"`
	ProtosSize      uint32   `pack:"uint"`
	ProtosOffset    uint32   `pack:"uint"`
	FieldsSize      uint32   `pack:"uint"`
	FieldsOffset    uint32   `pack:"uint"`
	MethodIdsSize   uint32   `pack:"uint"`
	MethodIdsOffset uint32   `pack:"uint"`
	ClassDefsSize   uint32   `pack:"uint"`
	ClassDefsOffset uint32   `pack:"uint"`
	DataSize        uint32   `pack:"uint"`
	DataOffset      uint32   `pack:"uint"`
}

func (h *Header) String() string {
	val := fmt.Sprintf("Magic: %x", h.Magic)
	val += fmt.Sprintf("\nChecksum: %x", h.Checksum)
	val += fmt.Sprintf("\nSignature: %x", h.Signature)
	val += fmt.Sprintf("\nFileSize: %d", h.FileSize)
	val += fmt.Sprintf("\nEndianTag: %x", h.EndianTag)
	return val
}

type ClassDefItem struct {
	dex                *DEX          `pack:"-"`
	ClassIdx           uint32        `pack:"uint"`
	AccessFlags        AccessFlags   `pack:"uint"`
	SuperclassIdx      uint32        `pack:"uint"`
	InterfacesOffset   uint32        `pack:"uint"`
	SourceFileIdx      uint32        `pack:"uint"`
	AnnotationsOffset  uint32        `pack:"uint"`
	ClassData          ClassDataItem `pack:"classdata"`
	StaticValuesOffset uint32        `pack:"uint"`
}

func (m *ClassDefItem) String() string {
	return fmt.Sprintf("%s %s", m.AccessFlags, m.dex.Strings[m.SourceFileIdx])
}

type FieldIdItem struct {
	dex      *DEX   `pack:"-"`
	ClassIdx uint16 `pack:"ushort"`
	TypeIdx  uint16 `pack:"ushort"`
	NameIdx  uint32 `pack:"uint"`
}

func (m *FieldIdItem) Type() string {
	return m.dex.Types[m.TypeIdx].String()
}

func (m *FieldIdItem) Class() string {
	return m.dex.Types[m.ClassIdx].String()
}

func (m *FieldIdItem) String() string {
	return fmt.Sprintf("%s", m.dex.Strings[m.NameIdx])
}

type EncodedField struct {
	dex          *DEX        `pack:"-"`
	Field        FieldIdItem `pack:"-"`
	FieldIdxDiff uint64      `pack:"uleb128"`
	AccessFlags  AccessFlags `pack:"uleb128"`
}

type EncodedMethod struct {
	dex           *DEX         `pack:"-"`
	Method        MethodIdItem `pack:"-"`
	MethodIdxDiff uint64       `pack:"uleb128"`
	AccessFlags   AccessFlags  `pack:"uleb128"`
	CodeOffset    uint64       `pack:"uleb128"`
}

type ClassDataItem struct {
	StaticFieldSize    uint64          `pack:"uleb128"`
	InstanceFieldSize  uint64          `pack:"uleb128"`
	DirectMethodsSize  uint64          `pack:"uleb128"`
	VirtualMethodsSize uint64          `pack:"uleb128"`
	StaticFields       []EncodedField  `pack:"staticfields"`
	InstanceFields     []EncodedField  `pack:"instancefields"`
	DirectMethods      []EncodedMethod `pack:"directmethods"`
	VirtualMethods     []EncodedMethod `pack:"virtualmethods"`
}

type MethodIdItem struct {
	dex      *DEX   `pack:"-"`
	ClassIdx uint16 `pack:"ushort"`
	ProtoIdx uint16 `pack:"ushort"`
	NameIdx  uint32 `pack:"uint"`
}

func (m *MethodIdItem) Proto() string {
	return m.dex.Prototypes[m.ProtoIdx].String()
}

func (m *MethodIdItem) Class() string {
	return m.dex.Types[m.ClassIdx].String()
}

func (m *MethodIdItem) Name() string {
	return m.dex.Strings[m.NameIdx]
}

func (m *MethodIdItem) String() string {
	return fmt.Sprintf("%s %s %s", m.Class(), m.Proto(), m.Name())
}

type ProtoIdItem struct {
	dex              *DEX   `pack:"-"`
	ShortyIdx        uint32 `pack:"uint"`
	ReturnTypeIdx    uint32 `pack:"uint"`
	ParametersOffset uint32 `pack:"uint"`
}

func (m *ProtoIdItem) String() string {
	return fmt.Sprintf("%s(%d) %s %d", m.dex.Strings[m.ShortyIdx], m.ShortyIdx, m.dex.Types[m.ReturnTypeIdx].String(), m.ParametersOffset)
}

type EncodedArray struct {
	Size uint64 `pack:"uleb128"`
	// Values []EncodedValues
}

type DEX struct {
	b          []byte
	header     Header
	Strings    []string
	Types      []TypeId
	Prototypes []ProtoIdItem
	Fields     []FieldIdItem
	Methods    []MethodIdItem
	Classes    []ClassDefItem
}

func (d *DEX) readHeader() error {
	_, err := Unpack(d.b, &d.header)
	return err
}

func (d *DEX) readFields() error {
	d.Fields = make([]FieldIdItem, d.header.FieldsSize)
	for i := 0; i < int(d.header.FieldsSize); i++ {
		s := uint32(d.header.FieldsOffset) + uint32(0x8*i)
		field_id_item := FieldIdItem{dex: d}
		if _, err := Unpack(d.b[s:], &field_id_item); err != nil {
			return err
		}

		d.Fields[i] = field_id_item
	}
	return nil
}

func (d *DEX) readMethods() error {
	d.Methods = make([]MethodIdItem, d.header.MethodIdsSize)
	for i := 0; i < int(d.header.MethodIdsSize); i++ {
		s := uint32(d.header.MethodIdsOffset) + uint32(0x8*i)
		method_id_item := MethodIdItem{dex: d}
		if _, err := Unpack(d.b[s:], &method_id_item); err != nil {
			return err
		}

		d.Methods[i] = method_id_item
	}
	return nil
}

type TypeId struct {
	dex           *DEX   `pack:"-"`
	DescriptorIdx uint32 `pack:"uint"`
}

func (t *TypeId) String() string {
	return fmt.Sprintf("%s", t.dex.Strings[t.DescriptorIdx])
}

func (d *DEX) readTypes() error {
	d.Types = make([]TypeId, d.header.TypeIdsSize)
	for i := 0; i < int(d.header.TypeIdsSize); i++ {
		typeid := TypeId{dex: d}
		if _, err := Unpack(d.b[d.header.TypeIdsOffset+uint32(4*i):], &typeid); err != nil {
			return err
		}

		d.Types[i] = typeid
	}
	return nil
}

func (d *DEX) readStrings() error {
	d.Strings = make([]string, d.header.StringIdsSize)

	var data = d.b[d.header.StringIdsOffset:]
	for i := 0; i < int(d.header.StringIdsSize); i++ {
		var offset = i * 4
		string_data_offset := binary.LittleEndian.Uint32(data[offset : offset+4])
		s, _ := str(d.b[string_data_offset:])
		d.Strings[i] = s
	}

	return nil
}

func (d *DEX) readPrototypes() error {
	d.Prototypes = make([]ProtoIdItem, d.header.ProtosSize)
	for i := 0; i < int(d.header.ProtosSize); i++ {
		s := uint32(d.header.ProtosOffset) + uint32(0xc*i)
		proto_id_item := ProtoIdItem{dex: d}
		if _, err := Unpack(d.b[s:], &proto_id_item); err != nil {
			return err
		}
		d.Prototypes[i] = proto_id_item
	}
	return nil
}

func (d *DEX) Dump() {
	fmt.Println("Types:")
	for i, t := range d.Types {
		fmt.Printf("%d %s\n", i, t.String())
	}

	fmt.Println("Prototypes:")
	for _, m := range d.Prototypes {
		fmt.Println(m.String())
	}

	fmt.Println("Classes:")
	for _, c := range d.Classes {
		fmt.Println(c.String())
		for _, f := range c.ClassData.InstanceFields {
			fmt.Printf("%s %s %s %s=\n", f.AccessFlags.String(), f.Field.Type(), f.Field.Class(), f.Field.String())
		}
		for _, f := range c.ClassData.StaticFields {
			fmt.Printf("%s %s %s %s=\n", f.AccessFlags.String(), f.Field.Type(), f.Field.Class(), f.Field.String())
		}

		for _, m := range c.ClassData.DirectMethods {
			fmt.Printf("%s()\n", m.Method.String())
		}
		for _, m := range c.ClassData.VirtualMethods {
			fmt.Printf("%s()\n", m.Method.String())
		}
	}
}

func (dex *DEX) Parse() error {
	if err := dex.readHeader(); err != nil {
		return err
	}

	if err := dex.readStrings(); err != nil {
		return err
	}

	if err := dex.readTypes(); err != nil {
		return err
	}

	if err := dex.readPrototypes(); err != nil {
		return err
	}

	if err := dex.readFields(); err != nil {
		return err
	}

	if err := dex.readMethods(); err != nil {
		return err
	}

	b := dex.b
	var err error
	header := dex.header

	_ = err

	dex.Classes = make([]ClassDefItem, header.ClassDefsSize)
	for i := 0; i < int(header.ClassDefsSize); i++ {
		s := uint32(header.ClassDefsOffset) + uint32(32*i)

		class_def_item := ClassDefItem{dex: dex}

		RegisterPack("classdata", PackFunc(func(data []byte, val reflect.Value) (uint, error) {
			// get class data offset
			var offset uint32
			length, err := packs["uint"](data, reflect.ValueOf(&offset).Elem())

			if offset == 0 {
				return length, err
			}

			// actually should use val
			_, _ = Unpack(b[offset:], &class_def_item.ClassData)
			return length, err
		}))

		RegisterPack("staticfields", PackFunc(func(data []byte, val reflect.Value) (uint, error) {
			class_def_item.ClassData.StaticFields = make([]EncodedField, class_def_item.ClassData.StaticFieldSize)

			offset := 0
			field_idx := uint64(0)
			for j := uint64(0); j < class_def_item.ClassData.StaticFieldSize; j++ {
				ef := EncodedField{dex: dex}
				length, _ := Unpack(data[offset:], &ef)
				field_idx += uint64(ef.FieldIdxDiff)
				ef.Field = dex.Fields[field_idx]
				offset += length
				class_def_item.ClassData.StaticFields[j] = ef
			}

			return uint(offset), nil
		}))

		RegisterPack("instancefields", PackFunc(func(data []byte, val reflect.Value) (uint, error) {
			class_def_item.ClassData.InstanceFields = make([]EncodedField, class_def_item.ClassData.InstanceFieldSize)
			offset := 0
			field_idx := uint64(0)
			for j := uint64(0); j < class_def_item.ClassData.InstanceFieldSize; j++ {
				ef := EncodedField{dex: dex}
				length, _ := Unpack(data[offset:], &ef)
				field_idx += uint64(ef.FieldIdxDiff)
				ef.Field = dex.Fields[field_idx]
				offset += length
				class_def_item.ClassData.InstanceFields[j] = ef
			}

			return uint(offset), nil
		}))

		RegisterPack("directmethods", PackFunc(func(data []byte, val reflect.Value) (uint, error) {
			class_def_item.ClassData.DirectMethods = make([]EncodedMethod, class_def_item.ClassData.DirectMethodsSize)
			offset := 0
			method_idx := uint64(0)
			for j := uint64(0); j < class_def_item.ClassData.DirectMethodsSize; j++ {
				em := EncodedMethod{dex: dex}
				length, _ := Unpack(data[offset:], &em)
				method_idx += uint64(em.MethodIdxDiff)
				em.Method = dex.Methods[method_idx]
				offset += length
				class_def_item.ClassData.DirectMethods[j] = em
			}
			return uint(offset), nil
		}))

		RegisterPack("virtualmethods", PackFunc(func(data []byte, val reflect.Value) (uint, error) {
			class_def_item.ClassData.VirtualMethods = make([]EncodedMethod, class_def_item.ClassData.VirtualMethodsSize)
			offset := 0
			method_idx := uint64(0)
			for j := uint64(0); j < class_def_item.ClassData.VirtualMethodsSize; j++ {
				em := EncodedMethod{dex: dex}
				length, _ := Unpack(data[offset:], &em)
				method_idx += uint64(em.MethodIdxDiff)
				em.Method = dex.Methods[method_idx]
				class_def_item.ClassData.VirtualMethods[j] = em
				offset += length
			}
			return uint(offset), nil
		}))

		var length int
		length, err = Unpack(b[s:], &class_def_item)

		dex.Classes[i] = class_def_item

		if class_def_item.StaticValuesOffset > 0 {
			b2 := class_def_item.StaticValuesOffset

			var ea EncodedArray
			length, err = Unpack(b[b2:], &ea)
			b2 += uint32(length)

		}

	}

	return nil
}

func Open(path string) (*DEX, error) {
	var err error
	var file *os.File
	if file, err = os.Open("classes.dex"); err != nil {
		return nil, err
	}

	var b []byte
	if b, err = ioutil.ReadAll(file); err != nil {
		return nil, err
	}

	dex := &DEX{b: b}
	dex.Parse()

	return dex, nil
}
