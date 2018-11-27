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

package main

import (
	"testing"

	"github.com/sero-cash/go-czero-import/cpt"
	"github.com/sero-cash/go-czero-import/keys"
)

func TestCpt(t *testing.T) {
	rad := cpt.Random()
	base58 := cpt.Base58Encode(rad[:])
	if base58 == nil {
		t.FailNow()
	}
	rad_ret := keys.Uint256{}
	e := cpt.Base58Decode(base58, rad_ret[:])
	if e != nil {
		t.FailNow()
	}
	if rad_ret != rad {
		t.FailNow()
	}
}

func TestKeys(t *testing.T) {
	seed := cpt.Random()
	tk := keys.Seed2Tk(&seed)
	pk := keys.Seed2Addr(&seed)

	if tk == pk {
		t.FailNow()
	}

	r := cpt.Random()
	pkr := keys.Addr2PKr(&pk, &r)
	is_my_pkr, _ := keys.IsMyPKr(&tk, &pkr)
	if !is_my_pkr {
		t.FailNow()
	}

	seed1 := cpt.Random()
	pk1 := keys.Seed2Addr(&seed1)
	tk1 := keys.Seed2Tk(&seed1)
	pkr1 := keys.Addr2PKr(&pk1, &r)
	is_my_pkr, _ = keys.IsMyPKr(&tk1, &pkr1)
	if !is_my_pkr {
		t.FailNow()
	}
	is_my_pkr_err, _ := keys.IsMyPKr(&tk, &pkr1)
	if is_my_pkr_err {
		t.FailNow()
	}

	h := cpt.Random()
	sign, err := keys.SignPKr(&seed, &h, &pkr)
	if err != nil {
		t.FailNow()
	}

	v_ok := keys.VerifyPKr(&h, &sign, &pkr)
	if !v_ok {
		t.FailNow()
	}

	v_ok_err := keys.VerifyPKr(&h, &sign, &pkr1)
	if v_ok_err {
		t.FailNow()
	}
}

func TestMain(m *testing.M) {
	cpt.ZeroInit(cpt.NET_Dev)
	m.Run()
}
