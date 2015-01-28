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
	dex               *DEX           `pack:"-"`
	ClassIdx          uint32         `pack:"uint"`
	AccessFlags       AccessFlags    `pack:"uint"`
	SuperclassIdx     uint32         `pack:"uint"`
	InterfacesOffset  uint32         `pack:"uint"`
	SourceFileIdx     uint32         `pack:"uint"`
	AnnotationsOffset uint32         `pack:"uint"`
	ClassData         ClassDataItem  `pack:"classdata"`
	StaticValues      []EncodedValue `pack:"staticvalues"`
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

const (
	VALUE_BYTE       = 0x00
	VALUE_SHORT      = 0x02
	VALUE_CHAR       = 0x03
	VALUE_INT        = 0x04
	VALUE_LONG       = 0x06
	VALUE_FLOAT      = 0x10
	VALUE_DOUBLE     = 0x11
	VALUE_STRING     = 0x17
	VALUE_TYPE       = 0x18
	VALUE_FIELD      = 0x19
	VALUE_METHOD     = 0x1a
	VALUE_ENUM       = 0x1b
	VALUE_ARRAY      = 0x1c
	VALUE_ANNOTATION = 0x1d
	VALUE_NULL       = 0x1e
	VALUE_BOOLEAN    = 0x1f
)

type ValueType uint32

func (vt ValueType) String() string {
	switch vt {
	case VALUE_BYTE:
		return "byte"
	case VALUE_SHORT:
		return "short"
	case VALUE_CHAR:
		return "char"
	case VALUE_INT:
		return "int"
	case VALUE_LONG:
		return "long"
	case VALUE_FLOAT:
		return "float"
	case VALUE_DOUBLE:
		return "double"
	case VALUE_STRING:
		return "string"
	case VALUE_TYPE:
		return "type"
	case VALUE_FIELD:
		return "field"
	case VALUE_METHOD:
		return "method"
	case VALUE_ENUM:
		return "enum"
	case VALUE_ARRAY:
		return "array"
	case VALUE_ANNOTATION:
		return "annotation"
	case VALUE_NULL:
		return "null"
	case VALUE_BOOLEAN:
		return "boolean"
	}

	return "UNKNOWN"
}

type EncodedValue struct {
	dex       *DEX      `pack:"-"`
	ValueType ValueType `pack:"-"`
	Data      []byte    `pack:"-"`
}

type EncodedArray struct {
	Size   uint64         `pack:"uleb128"`
	Values []EncodedValue `pack:"encodedvalue"`
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

type Instruction struct {
	Name   string
	Length int
}

var instructions map[byte]Instruction = map[byte]Instruction{
	0x00: Instruction{Name: "nop", Length: 0},
	0x01: Instruction{Name: "move vA, vB", Length: 1},
	0x02: Instruction{Name: "move/from16 vAA, vBBBB", Length: 3},
	0x03: Instruction{Name: "move/16 vAAAA, vBBBB", Length: 4},
	0x04: Instruction{Name: "move-wide vA, vB", Length: 1},
	0x05: Instruction{Name: "move-wide/from16 vAA, vBBBB", Length: 3},
	0x06: Instruction{Name: "move-wide/16 vAAAA, vBBBB", Length: 4},
	0x07: Instruction{Name: "move-object vA, vB", Length: 1},
	0x08: Instruction{Name: "move-object/from16 vAA, vBBBB", Length: 3},
	0x09: Instruction{Name: "move-object/16 vAAAA, vBBBB", Length: 4},
	0x0a: Instruction{Name: "move-result vAA", Length: 1},
	0x0b: Instruction{Name: "move-result-wide vAA", Length: 1},
	0x0c: Instruction{Name: "move-result-object vAA", Length: 1},
	0x0d: Instruction{Name: "move-exception vAA", Length: 1},
	0x0e: Instruction{Name: "return-void", Length: 1},
	0x0f: Instruction{Name: "return vAA", Length: 1},
	0x10: Instruction{Name: "return-wide vAA", Length: 1},
	0x11: Instruction{Name: "return-object vAA", Length: 1},
	0x12: Instruction{Name: "const/4 vA, #+B", Length: 1},
	0x13: Instruction{Name: "const/16 vAA, #+BBBB", Length: 3},
	0x14: Instruction{Name: "const vAA, #+BBBBBBBB", Length: 5},
	0x15: Instruction{Name: "const/high16 vAA, #+BBBB0000", Length: 5},
	0x16: Instruction{Name: "const-wide/16 vAA, #+BBBB", Length: 3},
	0x17: Instruction{Name: "const-wide/32 vAA, #+BBBBBBBB", Length: 5},
	0x18: Instruction{Name: "const-wide vAA, #+BBBBBBBBBBBBBBBB", Length: 9},
	0x19: Instruction{Name: "const-wide/high16 vAA, #+BBBB000000000000", Length: 9},
	0x1a: Instruction{Name: "const-string vAA, string@BBBB", Length: 3},
	0x1b: Instruction{Name: "const-string/jumbo vAA, string@BBBBBBBB", Length: 5},
	0x1c: Instruction{Name: "const-class vAA, type@BBBB", Length: 3},
	0x1d: Instruction{Name: "monitor-enter vAA", Length: 1},
	0x1e: Instruction{Name: "monitor-exit vAA", Length: 1},
	0x1f: Instruction{Name: "check-cast vAA, type@BBBB", Length: 3},
	0x20: Instruction{Name: "instance-of vA, vB, type@CCCC", Length: 3},
	0x21: Instruction{Name: "array-length vA, vB", Length: 1},
	0x22: Instruction{Name: "new-instance vAA, type@BBBB", Length: 3},
	0x23: Instruction{Name: "new-array vA, vB, type@CCCC", Length: 3},
	0x24: Instruction{Name: "filled-new-array {Name:vC, vD, vE, vF, vG}, type@BBBB", Length: -1},
	0x25: Instruction{Name: "filled-new-array/range {Name:vCCCC .. vNNNN}, type@BBBB", Length: -1},
	0x26: Instruction{Name: "fill-array-data vAA, +BBBBBBBB", Length: -1},
	0x27: Instruction{Name: "throw vAA", Length: 1},
	0x28: Instruction{Name: "goto +AA", Length: 1},
	0x29: Instruction{Name: "goto/16 +AAAA", Length: 2},
	0x2a: Instruction{Name: "goto/32 +AAAAAAAA", Length: 4},
	0x2b: Instruction{Name: "packed-switch vAA, +BBBBBBBB", Length: -1},
	0x2c: Instruction{Name: "sparse-switch vAA, +BBBBBBBB", Length: -1},
	0x2d: Instruction{Name: "cmpl-float vAA, vBB, vCC", Length: 3},
	0x2e: Instruction{Name: "cmpg-float vAA, vBB, vCC", Length: 3},
	0x2f: Instruction{Name: "cmpl-double vAA, vBB, vCC", Length: 3},
	0x30: Instruction{Name: "cmplg-double vAA, vBB, vCC", Length: 3},
	0x31: Instruction{Name: "cmp-long vAA, vBB, vCC", Length: 3},
	0x32: Instruction{Name: "if-eq vA, vB, +CCCC", Length: 3},
	0x33: Instruction{Name: "if-ne vA, vB, +CCCC", Length: 3},
	0x34: Instruction{Name: "if-lt vA, vB, +CCCC", Length: 3},
	0x35: Instruction{Name: "if-ge vA, vB, +CCCC", Length: 3},
	0x36: Instruction{Name: "if-gt vA, vB, +CCCC", Length: 3},
	0x37: Instruction{Name: "if-le vA, vB, +CCCC", Length: 3},
	0x38: Instruction{Name: "if-eqz vAA, +BBBB", Length: 3},
	0x39: Instruction{Name: "if-nez vAA, +BBBB", Length: 3},
	0x3a: Instruction{Name: "if-ltz vAA, +BBBB", Length: 3},
	0x3b: Instruction{Name: "if-gez vAA, +BBBB", Length: 3},
	0x3c: Instruction{Name: "if-gtz vAA, +BBBB", Length: 3},
	0x3d: Instruction{Name: "if-lez vAA, +BBBB", Length: 3},
	0x44: Instruction{Name: "aget vAA, vBB, vCC", Length: -1},
	0x45: Instruction{Name: "aget-wide vAA, vBB, vCC", Length: -1},
	0x46: Instruction{Name: "aget-object vAA, vBB, vCC", Length: -1},
	0x47: Instruction{Name: "aget-boolean vAA, vBB, vCC", Length: -1},
	0x48: Instruction{Name: "aget-byte vAA, vBB, vCC", Length: -1},
	0x49: Instruction{Name: "aget-char vAA, vBB, vCC", Length: -1},
	0x4a: Instruction{Name: "aget-short vAA, vBB, vCC", Length: -1},
	0x4b: Instruction{Name: "aput vAA, vBB, vCC", Length: -1},
	0x4c: Instruction{Name: "aput-wide vAA, vBB, vCC", Length: -1},
	0x4d: Instruction{Name: "aput-object vAA, vBB, vCC", Length: -1},
	0x4e: Instruction{Name: "aput-boolean vAA, vBB, vCC", Length: -1},
	0x4f: Instruction{Name: "aput-byte vAA, vBB, vCC", Length: -1},
	0x50: Instruction{Name: "aput-char vAA, vBB, vCC", Length: -1},
	0x51: Instruction{Name: "aput-short vAA, vBB, vCC", Length: -1},
	0x52: Instruction{Name: "iget vA, vB, field@CCCC", Length: 3},
	0x53: Instruction{Name: "iget-wide vA, vB, field@CCCC", Length: 3},
	0x54: Instruction{Name: "iget-object vA, vB, field@CCCC", Length: 3},
	0x55: Instruction{Name: "iget-boolean vA, vB, field@CCCC", Length: 3},
	0x56: Instruction{Name: "iget-byte vA, vB, field@CCCC", Length: 3},
	0x57: Instruction{Name: "iget-char vA, vB, field@CCCC", Length: 3},
	0x58: Instruction{Name: "iget-short vA, vB, field@CCCC", Length: 3},
	0x59: Instruction{Name: "iput vA, vB, field@CCCC", Length: 3},
	0x5a: Instruction{Name: "iput-wide vA, vB, field@CCCC", Length: 3},
	0x5b: Instruction{Name: "iput-object vA, vB, field@CCCC", Length: 3},
	0x5c: Instruction{Name: "iput-boolean vA, vB, field@CCCC", Length: 3},
	0x5d: Instruction{Name: "iput-byte vA, vB, field@CCCC", Length: 3},
	0x5e: Instruction{Name: "iput-char vA, vB, field@CCCC", Length: 3},
	0x5f: Instruction{Name: "iput-short vA, vB, field@CCCC", Length: 3},
	0x60: Instruction{Name: "sget vAA, field@BBBB", Length: 3},
	0x61: Instruction{Name: "sget-wide vAA, field@BBBB", Length: 3},
	0x62: Instruction{Name: "sget-object vAA, field@BBBB", Length: 3},
	0x63: Instruction{Name: "sget-boolean vAA, field@BBBB", Length: 3},
	0x64: Instruction{Name: "sget-byte vAA, field@BBBB", Length: 3},
	0x65: Instruction{Name: "sget-char vAA, field@BBBB", Length: 3},
	0x66: Instruction{Name: "sget-short vAA, field@BBBB", Length: 3},
	0x67: Instruction{Name: "sput vAA, field@BBBB", Length: 3},
	0x68: Instruction{Name: "sput-wide vAA, field@BBBB", Length: 3},
	0x69: Instruction{Name: "sput-object vAA, field@BBBB", Length: 3},
	0x6a: Instruction{Name: "sput-boolean vAA, field@BBBB", Length: 3},
	0x6b: Instruction{Name: "sput-byte vAA, field@BBBB", Length: 3},
	0x6c: Instruction{Name: "sput-char vAA, field@BBBB", Length: 3},
	0x6d: Instruction{Name: "sput-short vAA, field@BBBB", Length: 3},
	0x6e: Instruction{Name: "invoke-virtual {Name:vC, vD, vE, vF, vG}, meth@BBBB", Length: 5},
	0x6f: Instruction{Name: "invoke-super {Name:vC, vD, vE, vF, vG}, meth@BBBB", Length: 5},
	0x70: Instruction{Name: "invoke-direct {Name:vC, vD, vE, vF, vG}, meth@BBBB", Length: 5},
	0x71: Instruction{Name: "invoke-static {Name:vC, vD, vE, vF, vG}, meth@BBBB", Length: 5},
	0x72: Instruction{Name: "invoke-interface {Name:vC, vD, vE, vF, vG}, meth@BBBB", Length: 5},
	0x74: Instruction{Name: "invoke-virtual/range {Name:vCCCC .. vNNNN}, meth@BBBB", Length: 5},
	0x75: Instruction{Name: "invoke-super/range {Name:vCCCC .. vNNNN}, meth@BBBB", Length: 5},
	0x76: Instruction{Name: "invoke-direct/range {Name:vCCCC .. vNNNN}, meth@BBBB", Length: 5},
	0x77: Instruction{Name: "invoke-static/range {Name:vCCCC .. vNNNN}, meth@BBBB", Length: 5},
	0x78: Instruction{Name: "invoke-interface/range {Name:vCCCC .. vNNNN}, meth@BBBB", Length: 5},
	0x7b: Instruction{Name: "neg-int vA, vB", Length: 1},
	0x7c: Instruction{Name: "not-int vA, vB", Length: 1},
	0x7d: Instruction{Name: "neg-long vA, vB", Length: 1},
	0x7e: Instruction{Name: "not-long vA, vB", Length: 1},
	0x7f: Instruction{Name: "neg-float vA, vB", Length: 1},
	0x80: Instruction{Name: "neg-double vA, vB", Length: 1},
	0x81: Instruction{Name: "int-to-long vA, vB", Length: 1},
	0x82: Instruction{Name: "int-to-float vA, vB", Length: 1},
	0x83: Instruction{Name: "int-to-double vA, vB", Length: 1},
	0x84: Instruction{Name: "long-to-int vA, vB", Length: 1},
	0x85: Instruction{Name: "long-to-float vA, vB", Length: 1},
	0x86: Instruction{Name: "long-to-double vA, vB", Length: 1},
	0x87: Instruction{Name: "float-to-int vA, vB", Length: 1},
	0x88: Instruction{Name: "float-to-long vA, vB", Length: 1},
	0x89: Instruction{Name: "float-to-double vA, vB", Length: 1},
	0x8a: Instruction{Name: "double-to-int vA, vB", Length: 1},
	0x8b: Instruction{Name: "double-to-long vA, vB", Length: 1},
	0x8c: Instruction{Name: "double-to-float vA, vB", Length: 1},
	0x8d: Instruction{Name: "int-to-byte vA, vB", Length: 1},
	0x8e: Instruction{Name: "int-to-char vA, vB", Length: 1},
	0x8f: Instruction{Name: "int-to-short vA, vB", Length: 1},
	0x90: Instruction{Name: "add-int vAA, vBB, vCC", Length: 3},
	0x91: Instruction{Name: "sub-int vAA, vBB, vCC", Length: 3},
	0x92: Instruction{Name: "mul-int vAA, vBB, vCC", Length: 3},
	0x93: Instruction{Name: "div-int vAA, vBB, vCC", Length: 3},
	0x94: Instruction{Name: "rem-int vAA, vBB, vCC", Length: 3},
	0x95: Instruction{Name: "and-int vAA, vBB, vCC", Length: 3},
	0x96: Instruction{Name: "or-int vAA, vBB, vCC", Length: 3},
	0x97: Instruction{Name: "xor-int vAA, vBB, vCC", Length: 3},
	0x98: Instruction{Name: "shl-int vAA, vBB, vCC", Length: 3},
	0x99: Instruction{Name: "shr-int vAA, vBB, vCC", Length: 3},
	0x9a: Instruction{Name: "ushr-int vAA, vBB, vCC", Length: 3},
	0x9b: Instruction{Name: "add-long vAA, vBB, vCC", Length: 3},
	0x9c: Instruction{Name: "sub-long vAA, vBB, vCC", Length: 3},
	0x9d: Instruction{Name: "mul-long vAA, vBB, vCC", Length: 3},
	0x9e: Instruction{Name: "div-long vAA, vBB, vCC", Length: 3},
	0x9f: Instruction{Name: "rem-long vAA, vBB, vCC", Length: 3},
	0xA0: Instruction{Name: "and-long vAA, vBB, vCC", Length: 3},
	0xA1: Instruction{Name: "or-long vAA, vBB, vCC", Length: 3},
	0xA2: Instruction{Name: "xor-long vAA, vBB, vCC", Length: 3},
	0xA3: Instruction{Name: "shl-long vAA, vBB, vCC", Length: 3},
	0xA4: Instruction{Name: "shr-long vAA, vBB, vCC", Length: 3},
	0xA5: Instruction{Name: "ushr-long vAA, vBB, vCC", Length: 3},
	0xA6: Instruction{Name: "add-float vAA, vBB, vCC", Length: 3},
	0xA7: Instruction{Name: "sub-float vAA, vBB, vCC", Length: 3},
	0xA8: Instruction{Name: "mul-float vAA, vBB, vCC", Length: 3},
	0xA9: Instruction{Name: "div-float vAA, vBB, vCC", Length: 3},
	0xAA: Instruction{Name: "rem-float vAA, vBB, vCC", Length: 3},
	0xAB: Instruction{Name: "add-double vAA, vBB, vCC", Length: 3},
	0xAC: Instruction{Name: "sub-double vAA, vBB, vCC", Length: 3},
	0xAD: Instruction{Name: "mul-double vAA, vBB, vCC", Length: 3},
	0xAE: Instruction{Name: "div-double vAA, vBB, vCC", Length: 3},
	0xAF: Instruction{Name: "rem-double vAA, vBB, vCC", Length: 3},
	0xB0: Instruction{Name: "add-int/2addr vA, vB", Length: 1},
	0xB1: Instruction{Name: "sub-int2addr vA, vB", Length: 1},
	0xB2: Instruction{Name: "mul-int/2addr vA, vB", Length: 1},
	0xB3: Instruction{Name: "div-int/2addr vA, vB", Length: 1},
	0xB4: Instruction{Name: "rem-int/2addr vA, vB", Length: 1},
	0xB5: Instruction{Name: "and-int/2addr vA, vB", Length: 1},
	0xB6: Instruction{Name: "or-int/2addr vA, vB", Length: 1},
	0xB7: Instruction{Name: "xor-int/2addr vA, vB", Length: 1},
	0xB8: Instruction{Name: "shl-int/2addr vA, vB", Length: 1},
	0xB9: Instruction{Name: "shr-int/2addr vA, vB", Length: 1},
	0xBa: Instruction{Name: "ushr-int/2addr vA, vB", Length: 1},
	0xBb: Instruction{Name: "add-long/2addr vA, vB", Length: 1},
	0xBc: Instruction{Name: "sub-long/2addr vA, vB", Length: 1},
	0xBd: Instruction{Name: "mul-long/2addr vA, vB", Length: 1},
	0xBe: Instruction{Name: "div-long/2addr vA, vB", Length: 1},
	0xBf: Instruction{Name: "rem-long/2addr vA, vB", Length: 1},
	0xc0: Instruction{Name: "and-long/2addr vA, vB", Length: 1},
	0xc1: Instruction{Name: "or-long/2addr vA, vB", Length: 1},
	0xc2: Instruction{Name: "xor-long/2addr vA, vB", Length: 1},
	0xc3: Instruction{Name: "shl-long/2addr vA, vB", Length: 1},
	0xc4: Instruction{Name: "shr-long/2addr vA, vB", Length: 1},
	0xc5: Instruction{Name: "ushr-long/2addr vA, vB", Length: 1},
	0xc6: Instruction{Name: "add-float/2addr vA, vB", Length: 1},
	0xc7: Instruction{Name: "sub-float/2addr vA, vB", Length: 1},
	0xc8: Instruction{Name: "mul-float/2addr vA, vB", Length: 1},
	0xc9: Instruction{Name: "div-float/2addr vA, vB", Length: 1},
	0xca: Instruction{Name: "rem-float/2addr vA, vB", Length: 1},
	0xcb: Instruction{Name: "add-double/2addr vA, vB", Length: 1},
	0xcc: Instruction{Name: "sub-double/2addr vA, vB", Length: 1},
	0xcd: Instruction{Name: "mul-double/2addr vA, vB", Length: 1},
	0xce: Instruction{Name: "div-double/2addr vA, vB", Length: 1},
	0xcf: Instruction{Name: "rem-double/2addr vA, vB", Length: 1},
	0xd0: Instruction{Name: "add-int/lit16 vA, vB, #+CCCC", Length: 3},
	0xd1: Instruction{Name: "rsub-int/lit16 vA, vB, #+CCCC", Length: 3},
	0xd2: Instruction{Name: "mul-int/lit16 vA, vB, #+CCCC", Length: 3},
	0xd3: Instruction{Name: "div-int/lit16 vA, vB, #+CCCC", Length: 3},
	0xd4: Instruction{Name: "rem-int/lit16 vA, vB, #+CCCC", Length: 3},
	0xd5: Instruction{Name: "and-int/lit16 vA, vB, #+CCCC", Length: 3},
	0xd6: Instruction{Name: "or-int/lit16 vA, vB, #+CCCC", Length: 3},
	0xd7: Instruction{Name: "xor-int/lit16 vA, vB, #+CCCC", Length: 3},
	0xd8: Instruction{Name: "add-int/lit8 vAA, vBB, #+CC", Length: 3},
	0xd9: Instruction{Name: "rsub-int/lit8 vAA, vBB, #+CC", Length: 3},
	0xda: Instruction{Name: "mul-int/lit8 vAA, vBB, #+CC", Length: 3},
	0xdb: Instruction{Name: "div-int/lit8 vAA, vBB, #+CC", Length: 3},
	0xdc: Instruction{Name: "rem-int/lit8 vAA, vBB, #+CC", Length: 3},
	0xdd: Instruction{Name: "and-int/lit8 vAA, vBB, #+CC", Length: 3},
	0xde: Instruction{Name: "or-int/lit8 vAA, vBB, #+CC", Length: 3},
	0xdf: Instruction{Name: "xor-int/lit8 vAA, vBB, #+CC", Length: 3},
	0xe0: Instruction{Name: "shl-int/lit8 vAA, vBB, #+CC", Length: 3},
	0xe1: Instruction{Name: "shr-int/lit8 vAA, vBB, #+CC", Length: 3},
	0xe2: Instruction{Name: "ushr-int/lit8 vAA, vBB, #+CC", Length: 3},
}

func (m *EncodedMethod) Disassemble() error {
	fmt.Println("*****")
	fmt.Println(m.CodeOffset)

	offset := int(m.CodeOffset)

	offset += 12

	// size
	size := int(binary.LittleEndian.Uint32(m.dex.b[offset : offset+4]))

	fmt.Printf("Size: %d\n", size)
	offset += 4

	// check opcode
	for offset < int(m.CodeOffset)+16+(size*2) {
		instruction_code := m.dex.b[offset]
		if instruction, ok := instructions[instruction_code]; ok {
			str := fmt.Sprintf("%0.2x %s", instruction_code, instruction.Name)

			offset += 1

			/*
				const string v5 = "Y"
				v6 = this.getStateVal()
				if String.equals(v5, v6) != 0 {
					return
				}*/

			if instruction_code == 0x6e || instruction_code == 0x6f || instruction_code == 0x70 || instruction_code == 0x71 {
				// variable arguments
				// fmt.Println("%d %d", int(m.dex.b[offset]), (int(m.dex.b[offset]) & 0xF0 >> 4))
				// fmt.Println("%d args", (4+((int(m.dex.b[offset])&0xF0)<<4)*4)/8)
				// offset += (4 + (((int(m.dex.b[offset]) & 0xF0) >> 4) * 4)) / 8
				//fmt.Printf("%x %x\n", offset, m.dex.b[offset+3:offset+5])
				methodIdx := int(binary.LittleEndian.Uint16(m.dex.b[offset+1 : offset+3]))
				str += " #" + m.dex.Methods[methodIdx].Name()
			} else if instruction_code == 0x72 || instruction_code == 0x73 || instruction_code == 0x74 {
				// variable arguments
				// fmt.Println("%d %d", int(m.dex.b[offset]), (int(m.dex.b[offset]) & 0xF0 >> 4))
				// fmt.Println("%d args", (4+((int(m.dex.b[offset])&0xF0)<<4)*4)/8)
				// offset += (4 + (((int(m.dex.b[offset]) & 0xF0) >> 4) * 4)) / 8
				//fmt.Printf("%x %x\n", offset, m.dex.b[offset+3:offset+5])
				methodIdx := int(binary.LittleEndian.Uint16(m.dex.b[offset+1 : offset+3]))
				str += " #" + m.dex.Methods[methodIdx].Name()
			} else if instruction_code == 0x22 {
				register := int(m.dex.b[offset])
				typeIdx := int(binary.LittleEndian.Uint16(m.dex.b[offset+1 : offset+3]))
				str += fmt.Sprintf(" # %d=%s", register, m.dex.Types[typeIdx].String())
			} else if instruction_code == 0x39 {
				register := int(m.dex.b[offset])
				str += fmt.Sprintf(" # Register: %d", register)
			} else if instruction_code == 0x07 {
				dest := int(m.dex.b[offset] & 0x0F)
				src := int(m.dex.b[offset]&0xF0) >> 4
				str += fmt.Sprintf(" # Register: %d = %d ", dest, src)
			} else if instruction_code == 0x12 {
				register := int(m.dex.b[offset] & 0x0F)
				value := int(m.dex.b[offset]&0xF0) >> 4
				str += fmt.Sprintf(" # Register: %d = %d ", register, value)
			} else if instruction_code == 0x0a || instruction_code == 0xb || instruction_code == 0x0c {
				// vAA
				register := int(m.dex.b[offset])
				str += fmt.Sprintf(" # Register: %d", register)
			} else if instruction_code == 0x1a {
				register := int(m.dex.b[offset])
				str += fmt.Sprintf(" # Register: %d", register)
				stringIdx := int(binary.LittleEndian.Uint16(m.dex.b[offset+1 : offset+3]))
				str += fmt.Sprintf(" # %d=%s", register, m.dex.Strings[stringIdx])
			} else if instruction.Length != -1 {
			} else {
				fmt.Printf("Invalid opcode %x\n", instruction_code)
				break
			}
			offset += instruction.Length
			fmt.Println(str)
			continue
		}
		break
	}

	fmt.Println("*****")
	return nil
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
			m.Disassemble()
		}
		for _, m := range c.ClassData.VirtualMethods {
			fmt.Printf("%s()\n", m.Method.String())
			m.Disassemble()
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

		RegisterPack("staticvalues", PackFunc(func(data []byte, val reflect.Value) (uint, error) {
			// get class data offset
			var offset uint32
			length, err := packs["uint"](data, reflect.ValueOf(&offset).Elem())
			if offset == 0 {
				return length, err
			}

			// actually should use val

			var size uint64
			length, err = packs["uleb128"](b[offset:], reflect.ValueOf(&size).Elem())

			offset += uint32(length)

			class_def_item.StaticValues = make([]EncodedValue, size)

			for j := uint64(0); j < size; j++ {
				ev := EncodedValue{dex: dex}

				var val uint32
				length, _ = packs["ubyte"](b[offset:], reflect.ValueOf(&val).Elem())
				valueType := ValueType(val & 0x1f)
				size2 := (uint64(val&0xE0) >> 5)

				fmt.Printf("ValueType:%d size:%d type:%d %s\n", val, size2, valueType, valueType.String())

				if valueType == VALUE_STRING {
					var stringIdx uint32
					for k := uint64(0); k <= size2; k++ {
						stringIdx = stringIdx + uint32(b[offset+1+uint32(k)])<<(k*8)
					}
					str := dex.Strings[stringIdx]
					fmt.Printf("stringidx %d %d %s\n", b[offset+1], stringIdx, str)
				} else if valueType == VALUE_INT {
					// SIGNED
				}

				offset += (uint32(val) & 0x0E) >> 5

				class_def_item.StaticValues[j] = ev
			}

			// _, _ = Unpack(b[offset:], &ea)
			return length, err
		}))

		_, err = Unpack(b[s:], &class_def_item)

		dex.Classes[i] = class_def_item

		/*
			if class_def_item.StaticValuesOffset > 0 {
				b2 := class_def_item.StaticValuesOffset

				var ea EncodedArray
				length, err = Unpack(b[b2:], &ea)
				b2 += uint32(length)
			}*/

	}

	return nil
}

func Open(path string) (*DEX, error) {
	var err error
	var file *os.File
	if file, err = os.Open(path); err != nil {
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
