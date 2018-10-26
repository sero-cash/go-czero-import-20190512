// Copyright 2015 The sero.cash Authors
// This file is part of the sero.cash library.
//
// The libzero library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The libzero library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the libzero library. If not, see <http://www.gnu.org/licenses/>.

package cpt

/*
#cgo CFLAGS: -I ../czero/include
#cgo LDFLAGS: -L ../czero/lib -l czero
#include "zero.h"
*/
import "C"
import (
	"errors"
	"unsafe"

	"github.com/sero-cash/go-czero-import/keys"
)

var init_chan = make(chan bool)

type NetType uint8

const (
	NET_Dev   NetType = 0
	NET_Alpha NetType = 1
	NET_Beta  NetType = 2
)

func ZeroInit(netType NetType) error {
	go func() {
		C.zero_init(C.uchar(netType))
		init_chan <- true
	}()
	<-init_chan
	return nil
}

func Random() (out keys.Uint256) {
	C.zero_random32(
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	return
}

func Combine(l *keys.Uint256, r *keys.Uint256) (out keys.Uint256) {
	C.zero_sha256_two(
		(*C.uchar)(unsafe.Pointer(&l[0])),
		(*C.uchar)(unsafe.Pointer(&r[0])),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	return
}

func Sha256(d *keys.Uint256) (out keys.Uint256) {
	C.zero_sha256_one(
		(*C.uchar)(unsafe.Pointer(&d[0])),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	return
}

type Pre struct {
	I uint32
	R keys.Uint256
	Z [2]keys.Uint256 //I256
}
type Extra struct {
	Pre
	O      [2]keys.Uint256 //I256
	S1_ret keys.Uint256
}

type Out struct {
	Addr           keys.Uint512
	Value          keys.Uint256 //U256
	Info           keys.Uint512
	EText_ret      [ETEXT_WIDTH]byte
	Currency       keys.Uint256
	Commitment_ret keys.Uint256
}

type In struct {
	EText      [ETEXT_WIDTH]byte
	Commitment keys.Uint256
	Path       [DEPTH * 32]byte
	S1         keys.Uint256
	Index      uint32
	Currency   keys.Uint256
	Anchor     keys.Uint256
	Nil_ret    keys.Uint256
	Trace_ret  keys.Uint256
}

type Proof struct {
	G [PROOF_WIDTH]byte
}

type Common struct {
	Seed     keys.Uint256
	Hash_O   keys.Uint256
	Currency keys.Uint256
	C        [2]keys.Uint256
}

func GenCommitment(currency *keys.Uint256, pkr *keys.Uint512, value *keys.Uint256, text *keys.Uint512) (ret keys.Uint256) {
	C.zero_gen_commitment(
		(*C.uchar)(unsafe.Pointer(&currency[0])),
		(*C.uchar)(unsafe.Pointer(&pkr[0])),
		(*C.uchar)(unsafe.Pointer(&value[0])),
		(*C.uchar)(unsafe.Pointer(&text[0])),
		(*C.uchar)(unsafe.Pointer(&ret[0])),
	)
	return
}

func GenDesc_Z(common *Common, pre *Pre, extra *Extra, out *Out, in *In, proof *Proof) (e error) {
	ret := C.zero_gen_desc_z(
		(*C.uchar)(unsafe.Pointer(&common.Seed[0])),
		(*C.uchar)(unsafe.Pointer(&common.Hash_O[0])),
		(*C.uchar)(unsafe.Pointer(&common.Currency[0])),
		(*C.uchar)(unsafe.Pointer(&common.C[0][0])),
		(*C.uchar)(unsafe.Pointer(&common.C[1][0])),
		//-----pre----
		C.uint(pre.I),
		(*C.uchar)(unsafe.Pointer(&pre.R[0])),
		(*C.uchar)(unsafe.Pointer(&pre.Z[0][0])),
		(*C.uchar)(unsafe.Pointer(&pre.Z[1][0])),
		//----extra----
		(*C.uchar)(unsafe.Pointer(&extra.O[0][0])),
		(*C.uchar)(unsafe.Pointer(&extra.O[1][0])),
		C.uint(extra.I),
		(*C.uchar)(unsafe.Pointer(&extra.Z[0][0])),
		(*C.uchar)(unsafe.Pointer(&extra.Z[1][0])),
		(*C.uchar)(unsafe.Pointer(&extra.R[0])),
		(*C.uchar)(unsafe.Pointer(&extra.S1_ret[0])),
		//----out-----
		(*C.uchar)(unsafe.Pointer(&out.Addr[0])),
		(*C.uchar)(unsafe.Pointer(&out.Value[0])),
		(*C.uchar)(unsafe.Pointer(&out.Info[0])),
		(*C.uchar)(unsafe.Pointer(&out.EText_ret[0])),
		(*C.uchar)(unsafe.Pointer(&out.Commitment_ret[0])),
		//----in----
		(*C.uchar)(unsafe.Pointer(&in.EText[0])),
		(*C.uchar)(unsafe.Pointer(&in.Commitment[0])),
		(*C.uchar)(unsafe.Pointer(&in.Path[0])),
		C.uint(in.Index),
		(*C.uchar)(unsafe.Pointer(&in.S1[0])),
		(*C.uchar)(unsafe.Pointer(&in.Anchor[0])),
		(*C.uchar)(unsafe.Pointer(&in.Nil_ret[0])),
		(*C.uchar)(unsafe.Pointer(&in.Trace_ret[0])),
		(*C.uchar)(unsafe.Pointer(&proof.G[0])),
	)
	if ret == 0 {
		return
	} else {
		e = errors.New("gen desc z error")
		return
	}
}

type Info struct {
	Currency keys.Uint256
	Text     keys.Uint512
	R        keys.Uint256
	V        keys.Uint256 //U256
	Trace    keys.Uint256
}

func EncodeEInfo(tk *keys.Uint512, pkr *keys.Uint512, info *Info) (succ bool, einfo [ETEXT_WIDTH]byte, commitment keys.Uint256) {
	ret := C.zero_en_einfo(
		(*C.uchar)(unsafe.Pointer(&pkr[0])),
		(*C.uchar)(unsafe.Pointer(&tk[0])),
		(*C.uchar)(unsafe.Pointer(&info.Currency[0])),
		(*C.uchar)(unsafe.Pointer(&info.Text[0])),
		(*C.uchar)(unsafe.Pointer(&info.V[0])),
		(*C.uchar)(unsafe.Pointer(&einfo[0])),
		(*C.uchar)(unsafe.Pointer(&info.R[0])),
		(*C.uchar)(unsafe.Pointer(&commitment[0])),
		(*C.uchar)(unsafe.Pointer(&info.Trace[0])),
	)
	//fmt.Printf("\nr: ")
	//r.LogOut()
	//commitment.LogOut();

	if ret == C.char(0) {
		succ = true
		return
	} else {
		succ = false
		return
	}
}

func DecodeEInfo(tk *keys.Uint512, einfo *[ETEXT_WIDTH]byte, s1 *keys.Uint256, commitment *keys.Uint256) (info Info, e error) {
	vsk := keys.Uint256{}
	zpk := keys.Uint256{}
	copy(vsk[:], tk[:32])
	copy(zpk[:], tk[32:])
	ret := C.zero_de_einfo(
		(*C.uchar)(unsafe.Pointer(&vsk[0])),
		(*C.uchar)(unsafe.Pointer(&zpk[0])),
		(*C.uchar)(unsafe.Pointer(&einfo[0])),
		(*C.uchar)(unsafe.Pointer(&s1[0])),
		(*C.uchar)(unsafe.Pointer(&commitment[0])),
		(*C.uchar)(unsafe.Pointer(&info.Currency[0])),
		(*C.uchar)(unsafe.Pointer(&info.Text[0])),
		(*C.uchar)(unsafe.Pointer(&info.R[0])),
		(*C.uchar)(unsafe.Pointer(&info.V[0])),
		(*C.uchar)(unsafe.Pointer(&info.Trace[0])),
	)
	if ret != C.char(0) {
		e = errors.New("decode einfo error")
		return
	} else {
		return
	}
}

type PreV struct {
	I  uint32
	S1 keys.Uint256
}

type ExtraV struct {
	PreV
	O [2]keys.Uint256 //I256
}

type OutV struct {
	Commitment keys.Uint256
}

type InV struct {
	Anchor keys.Uint256
	Nil    keys.Uint256
}

func VerifyDesc_Z(hash_o *keys.Uint256, pre *PreV, extra *ExtraV, out *OutV, in *InV, proof *Proof) (e error) {
	ret := C.zero_verify_desc_z(
		(*C.uchar)(unsafe.Pointer(&hash_o[0])),
		C.uint(pre.I),
		(*C.uchar)(unsafe.Pointer(&pre.S1[0])),
		(*C.uchar)(unsafe.Pointer(&extra.O[0][0])),
		(*C.uchar)(unsafe.Pointer(&extra.O[1][0])),
		C.uint(extra.I),
		(*C.uchar)(unsafe.Pointer(&extra.S1[0])),
		(*C.uchar)(unsafe.Pointer(&out.Commitment[0])),
		(*C.uchar)(unsafe.Pointer(&in.Anchor[0])),
		(*C.uchar)(unsafe.Pointer(&in.Nil[0])),
		(*C.uchar)(unsafe.Pointer(&proof.G[0])),
	)
	if ret == 0 {
		return
	} else {
		e = errors.New("verify desc z failed")
		return
	}
}

func Base58Encode(bytes []byte) (ret *string) {
	str := C.zero_base58_enc(
		(*C.uchar)(unsafe.Pointer(&bytes[0])),
		C.int(len(bytes)),
	)
	if str != nil {
		defer C.zero_fee_str(str)
		s := C.GoString(str)
		ret = &s
		return
	} else {
		return
	}
}

func Base58Decode(str *string, bytes []byte) (e error) {
	ret := C.zero_base58_dec(
		C.CString(*str),
		(*C.uchar)(unsafe.Pointer(&bytes[0])),
		C.int(len(bytes)),
	)
	if ret == C.char(0) {
		return
	} else {
		e = errors.New("base58 can not decode string")
		return
	}
}
