/*
  Copyright (C) 2018 Simon Schmidt

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package boxpgp

import "golang.org/x/crypto/openpgp"
import message "github.com/emersion/go-message"
import "encoding/json"
import "bytes"
import "encoding/base64"
import "fmt"

import "compress/flate"

var envHeaders = []string{
	"Date",
	"Subject",
	"From",
	"Sender",
	"Reply-To",
	"To",
	"Cc",
	"Bcc",
	"In-Reply-To",
	"Message-Id",
}

const XPgpEnvelope = "X-Pgp-Envelope"

func log16(i int) (j int) {
	i>>=4
	j = 1
	for i>0 {
		i>>=4
		j++
	}
	return
}

/*
Encrypts the Envelope part of the header.
*/
func EncodeHeader(target, source message.Header,keys []*openpgp.Entity) (err error) {
	var result []string
	h := source
	comp := make([][]string,len(envHeaders))
	for i,n := range envHeaders {
		comp[i] = h[n]
	}
	buf := new(bytes.Buffer)
	enc := base64.NewEncoder(base64.RawStdEncoding,buf)
	w,e := openpgp.Encrypt(enc, keys, nil, nil, nil)// &openpgp.FileHints{IsBinary:true}
	if e!=nil { err = e; return }
	w2,e := flate.NewWriter(w,9)
	if e!=nil { err = e; return }
	e = json.NewEncoder(w2).Encode(comp)
	if e!=nil { err = e; return }
	
	w2.Close()
	w.Close()
	enc.Close()
	
	max := 70-(len(XPgpEnvelope)+4)
	result = make([]string,0,buf.Len()/max)
	num := 0
	for {
		part := buf.Next(max-log16(num))
		if len(part)==0 { break }
		result = append(result,fmt.Sprintf("%x-%s",num,part))
		num++
	}
	
	target[XPgpEnvelope] = result
	return
}

/*
Decrypts the envelope part of the header.
*/
func DecodeHeader(source message.Header,keys openpgp.KeyRing) (target message.Header, err error) {
	buf := new(bytes.Buffer)
	elems := make(map[int]string)
	
	for _,str := range source[XPgpEnvelope] {
		var part string
		var num int
		i,_ := fmt.Sscanf(str,"%x-%s",&num,&part)
		if i!=2 { continue }
		elems[num] = part
	}
	for i := 0 ; true ; i++ {
		part,ok := elems[i]
		if !ok { break }
		buf.WriteString(part)
	}
	
	r := base64.NewDecoder(base64.RawStdEncoding,buf)
	m,e := openpgp.ReadMessage(r, keys, nil, nil)
	if e!=nil { err = e; return }
	
	r2 := flate.NewReader(m.UnverifiedBody)
	defer r2.Close()
	
	var result [][]string
	err = json.NewDecoder(r2).Decode(&result)
	if err!=nil { return }
	EH := envHeaders
	if len(result)<len(EH) { EH = EH[:len(result)] }
	target = make(message.Header)
	for i,k := range EH {
		target[k] = result[i]
	}
	
	return
}

