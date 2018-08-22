/*
  Copyright (C) 2018 Simon Schmidt

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package boxpgp

import "golang.org/x/crypto/openpgp"
import "golang.org/x/crypto/openpgp/armor"
import message "github.com/emersion/go-message"
import "bytes"
import "io"
import "io/ioutil"

import "github.com/dsnet/compress/bzip2"

func EncryptMessage(raw []byte,keys []*openpgp.Entity) (result []byte,err error) {
	wr0 := new(bytes.Buffer)
	wr1,e := armor.Encode(wr0,"ENCLOSED-OPGP",make(map[string]string))
	if e!=nil { err = e ; return }
	wr2,e := openpgp.Encrypt(wr1,keys, nil, nil, nil)
	if e!=nil { err = e ; return }
	wr3,e := bzip2.NewWriter(wr2,&bzip2.WriterConfig{Level:9})
	if e!=nil { err = e ; return }
	_,err = wr3.Write(raw)
	if err!=nil { return }
	err = wr3.Close()
	if err!=nil { return }
	err = wr2.Close()
	if err!=nil { return }
	err = wr1.Close()
	if err!=nil { return }
	result = wr0.Bytes()
	return
}

func decryptMessage(body io.Reader,keys openpgp.KeyRing) (blk *armor.Block,err error) {
	blk,err = armor.Decode(body)
	if err!=nil { return }
	m,e := openpgp.ReadMessage(blk.Body, keys, nil, nil)
	if e!=nil { err = e; return }
	blk.Body,err = bzip2.NewReader(m.UnverifiedBody,new(bzip2.ReaderConfig))
	return
}

func DecryptMessage(body io.Reader,keys openpgp.KeyRing) (result []byte,err error) {
	blk,e := decryptMessage(body,keys)
	if e!=nil { err = e; return }
	return ioutil.ReadAll(blk.Body)
}

func EncryptEMail(raw []byte,hdr message.Header,keys []*openpgp.Entity) (result *message.Entity,err error) {
	msg,e := message.Read(bytes.NewReader(raw))
	if e!=nil { err = e ; return }
	if hdr==nil { hdr = make(message.Header) }
	err = EncodeHeader(hdr,msg.Header,keys)
	hdr.Set("Subject","<Enclosed-H>")
	hdr.Set("X-Encrypted","ENCLOSED-OPGP")
	wr0 := new(bytes.Buffer)
	wr1,e := armor.Encode(wr0,"ENCLOSED-OPGP",make(map[string]string))
	if e!=nil { err = e ; return }
	wr2,e := openpgp.Encrypt(wr1,keys, nil, nil, nil)
	if e!=nil { err = e ; return }
	wr3,e := bzip2.NewWriter(wr2,&bzip2.WriterConfig{Level:9})
	if e!=nil { err = e ; return }
	_,err = wr3.Write(raw)
	if err!=nil { return }
	err = wr3.Close()
	if err!=nil { return }
	err = wr2.Close()
	if err!=nil { return }
	err = wr1.Close()
	if err!=nil { return }
	lr := 0
	ovh := 0
	for k,vv := range hdr {
		ovh = len(k)+4 // ^<Key>: <Value>\r\n$
		for _,v := range vv { lr+= ovh+len(v) }
	}
	if lr>wr0.Len() {
		hdr.Set("Subject","<Enclosed-B>")
		delete(hdr,XPgpEnvelope)
	}
	result,err = message.New(hdr,wr0)
	return
}

