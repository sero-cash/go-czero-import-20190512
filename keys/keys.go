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

package keys

/*
#cgo CFLAGS: -I ../czero/include
#cgo LDFLAGS: -L ../czero/lib -l czero
#include "zero.h"
 */
import "C"

import (
    "encoding/hex"
    "unsafe"
	"crypto/rand"
)



type Uint256 [32]byte
type Uint512 [64]byte
type Uint128 [16]byte

func Seeds2Tks(seeds []Uint256) (tks []Uint512) {
    for _,seed:=range seeds {
        tks=append(tks,Seed2Tk(&seed))
    }
    return
}

func (b *Uint128) ToUint256() (ret Uint256) {
    copy(ret[:],b[:])
    return
}

var Empty_Uint256=Uint256{}
var Empty_Uint512=Uint512{}

func (self Uint256) NewRef()(ret *Uint256) {
    ret=&Uint256{}
    copy(ret[:],self[:])
    return ret;
}

func (self Uint256) LogOut() {
    logBytes(self[:])
}


func (self Uint512) NewRef()(ret *Uint512) {
    ret=&Uint512{}
    copy(ret[:],self[:])
    return ret;
}

func (self Uint512) LogOut() {
    logBytes(self[:])
}

func (b Uint256) MarshalText() ([]byte, error) {
    result := make([]byte, len(b)*2+2)
    copy(result, `0x`)
    hex.Encode(result[2:],b[:])
    return result, nil
}

func (b Uint512) MarshalText() ([]byte, error) {
    result := make([]byte, len(b)*2+2)
    copy(result, `0x`)
    hex.Encode(result[2:],b[:])
    return result, nil
}

func (b Uint128) MarshalText() ([]byte, error) {
    result := make([]byte, len(b)*2+2)
    copy(result, `0x`)
    hex.Encode(result[2:],b[:])
    return result, nil
}


func logBytes(bytes []byte) {
    C.zero_log_bytes(
        (*C.uchar)(unsafe.Pointer(&bytes[0])),
        (C.int)(len(bytes)),
    )
    return
}

func Seed2Tk(seed *Uint256) (tk Uint512) {
    C.zero_seed2tk(
        (*C.uchar)(unsafe.Pointer(&seed[0])),
        (*C.uchar)(unsafe.Pointer(&tk[0])),
    )
    return
}

func Seed2Addr(seed *Uint256) (addr Uint512) {
	C.zero_seed2pk(
		(*C.uchar)(unsafe.Pointer(&seed[0])),
		(*C.uchar)(unsafe.Pointer(&addr[0])),
	)
	return
}


func RandUint512() (hash Uint512) {
	rand.Read(hash[:])
    return
}

func RandUint256() (hash Uint256) {
	rand.Read(hash[:])
    return
}

func RandUint128() (hash Uint128) {
	rand.Read(hash[:])
    return
}

func Addr2PKr(addr *Uint512,r *Uint256) (pkr Uint512) {
    if r==nil {
        t:=RandUint256()
        r=&t
    } else {
        empty:=Uint256{}
        if (*r)==empty {
            panic("gen pkr, but r is empty")
        }
    }
    C.zero_pk2pkr(
        (*C.uchar)(unsafe.Pointer(&addr[0])),
        (*C.uchar)(unsafe.Pointer(&r[0])),
        (*C.uchar)(unsafe.Pointer(&pkr[0])),
    )
    return
}

func IsMyPKr(tk *Uint512,pkr *Uint512)(succ bool) {
    ret:=C.zero_ismy_pkr(
        (*C.uchar)(unsafe.Pointer(&pkr[0])),
        (*C.uchar)(unsafe.Pointer(&tk[0])),
    )
    if(ret==C.char(0)) {
        succ=true
        return
    } else {
        succ=false
        return
    }
}

func SignOAddr(seed * Uint256,data *Uint256,a *Uint256,R *Uint256) (sign Uint256,e error) {
    return
}

func VerifyOAddr(data *Uint256,sign *Uint256,R *Uint256) (bool) {
    return true
}