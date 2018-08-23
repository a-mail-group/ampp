/*
  Copyright (C) 2018 Simon Schmidt

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package cypherpunk

import "bytes"
import "bufio"
import "net/textproto"
import "regexp"
import "errors"
import "golang.org/x/crypto/openpgp"
import "golang.org/x/crypto/openpgp/armor"
import "github.com/a-mail-group/ampp/qmodel"
import "io/ioutil"
import "compress/flate"

var (
	ENotRemail = errors.New("No Remailer Message")
	EInvalidArmor = errors.New("Invalid ASCII armor")
	EUnknownEncryptio = errors.New("UnknownEncryption")
)

var (
	r_firstline = regexp.MustCompile(`^\s*::\s*\n`)
	r_afterline = regexp.MustCompile(`^\s*##\s*\n`)
)
func processBody(body []byte,myaddr string,ring openpgp.KeyRing) (qmsg *qmodel.Message,err error) {
restart:
	
	stream := bufio.NewReader(bytes.NewReader(body))
	begin,e := stream.ReadSlice('\n')
	if e!=nil { err = e; return }
	if !r_firstline.Match(begin) { err = ENotRemail; return }
	h,e := textproto.NewReader(stream).ReadMIMEHeader()
	if e!=nil { err = e; return }
	switch h.Get("Encrypted") {
	case "":
	case "PGP":
		blk,e := armor.Decode(stream)
		if e!=nil { err = e; return }
		if blk.Type!="PGP MESSAGE" { err = EInvalidArmor; return }
		cleartext,e := openpgp.ReadMessage(blk.Body,ring,nil,nil)
		if e!=nil { err = e; return }
		nbody,e := ioutil.ReadAll(cleartext.UnverifiedBody)
		if e!=nil { err = e; return }
		body = nbody
		goto restart
	case "ZPGP":
		blk,e := armor.Decode(stream)
		if e!=nil { err = e; return }
		if blk.Type!="ZPGP MESSAGE" { err = EInvalidArmor; return }
		cleartext,e := openpgp.ReadMessage(blk.Body,ring,nil,nil)
		if e!=nil { err = e; return }
		rc := flate.NewReader(cleartext.UnverifiedBody)
		nbody,e := ioutil.ReadAll(rc)
		rc.Close()
		if e!=nil { err = e; return }
		body = nbody
		goto restart
	default:
		err = EUnknownEncryptio
		return
	}
	
	begin,e = stream.ReadSlice('\n')
	if e!=nil { err = e; return }
	if !r_afterline.Match(begin) { err = ENotRemail; return }
	
	msg,e := ioutil.ReadAll(stream)
	if e!=nil { err = e; return }
	
	qmsg = &qmodel.Message{
		From:myaddr,
		To:h["Anon-To"],
		Body:msg,
	}
	return
}

/*
Processes a Message-Body that is assumed to be a Cypherpunk-Remailer message.
It returns nil,ENotRemail if the message is not a Cypherpunk-Remailer message.
*/
func ProcessMessage(msg []byte,myaddr string,ring openpgp.KeyRing) (qmsg *qmodel.Message,err error) {
	stream := bufio.NewReader(bytes.NewReader(msg))
	
	// We read and discard the MIME-Header.
	_,e := textproto.NewReader(stream).ReadMIMEHeader()
	if e!=nil { err = e; return }
	
	body,e := ioutil.ReadAll(stream)
	if e!=nil { err = e; return }
	
	return processBody(body,myaddr,ring)
}

