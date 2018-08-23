/*
  Copyright (C) 2018 Simon Schmidt

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

// Cypherpunk remailer client and server implementation.
package cypherpunk

import "bytes"
import "github.com/emersion/go-message"
import "github.com/a-mail-group/ampp/qmodel"
import "golang.org/x/crypto/openpgp"
import "golang.org/x/crypto/openpgp/armor"
import "fmt"
import "compress/flate"

/*
Wraps a message to be sent over a cypherpunk remailer.
*/
func WrapMessageCypherpunk(orig *qmodel.Message, remailer string, remailerKey *openpgp.Entity) (wrap *qmodel.Message, err error) {
	header := make(message.Header)
	header.Set("To",remailer)
	header.Set("From",orig.From)
	header.Set("Subject","Anonymous Message.")
	msgb := new(bytes.Buffer)
	msgw,e := message.CreateWriter(msgb, header)
	if e!=nil { err = e; return }
	
	_,e = fmt.Fprintf(msgw,"::\r\nEncrypted: PGP\r\n\r\n")
	if e!=nil { err = e; return }
	enc1,e := armor.Encode(msgw,"PGP MESSAGE",make(map[string]string))
	if e!=nil { err = e; return }
	enc2,e := openpgp.Encrypt(enc1,[]*openpgp.Entity{remailerKey},nil,nil,nil)
	if e!=nil { err = e; return }
	_,e = fmt.Fprint(enc2,"::\r\n")
	if e!=nil { err = e; return }
	header = make(message.Header)
	header["Anon-To"] = orig.To
	header.Set("Latent-Time","+0:00")
	encw,e := message.CreateWriter(enc2, header)
	if e!=nil { err = e; return }
	_,e = fmt.Fprint(encw,"##\r\n")
	if e!=nil { err = e; return }
	_,e = encw.Write(orig.Body)
	if e!=nil { err = e; return }
	
	e = encw.Close()
	if e!=nil { err = e; return }
	e = enc2.Close()
	if e!=nil { err = e; return }
	e = enc1.Close()
	if e!=nil { err = e; return }
	e = msgw.Close()
	if e!=nil { err = e; return }
	
	wrap = &qmodel.Message{
		From: orig.From,
		To: []string{remailer},
		Body: msgb.Bytes(),
	}
	return
}

const (
	BestSpeed   = flate.BestSpeed
	BestCompression = flate.BestCompression
	DefaultCompression = flate.DefaultCompression
	
	// Disables the Lempel-Ziv match searching and only performs Huffman
	// entropy encoding. This is useful to compress Base64 encoded ciphertexts
	// and E-Mail attachments.
	HuffmanOnly = flate.HuffmanOnly
)

/*
Works like WrapMessageCypherpunk() but compresses the data before encryption.
This is not compatible with standard PGP implementations and cypherpunk remailers.
*/
func WrapMessageCypherpunkCompressed(orig *qmodel.Message, remailer string, remailerKey *openpgp.Entity, level int) (wrap *qmodel.Message, err error) {
	if level==flate.NoCompression {
		return WrapMessageCypherpunk(orig,remailer,remailerKey)
	}
	header := make(message.Header)
	header.Set("To",remailer)
	header.Set("From",orig.From)
	header.Set("Subject","Anonymous Message.")
	msgb := new(bytes.Buffer)
	msgw,e := message.CreateWriter(msgb, header)
	if e!=nil { err = e; return }
	
	_,e = fmt.Fprintf(msgw,"::\r\nEncrypted: ZPGP\r\n\r\n")
	if e!=nil { err = e; return }
	enc1,e := armor.Encode(msgw,"ZPGP MESSAGE",make(map[string]string))
	if e!=nil { err = e; return }
	enc2,e := openpgp.Encrypt(enc1,[]*openpgp.Entity{remailerKey},nil,nil,nil)
	if e!=nil { err = e; return }
	enc3,e := flate.NewWriter(enc2,level)
	if e!=nil { err = e; return }
	_,e = fmt.Fprint(enc3,"::\r\n")
	if e!=nil { err = e; return }
	header = make(message.Header)
	header["Anon-To"] = orig.To
	header.Set("Latent-Time","+0:00")
	encw,e := message.CreateWriter(enc3, header)
	if e!=nil { err = e; return }
	_,e = fmt.Fprint(encw,"##\r\n")
	if e!=nil { err = e; return }
	_,e = encw.Write(orig.Body)
	if e!=nil { err = e; return }
	
	e = encw.Close()
	if e!=nil { err = e; return }
	e = enc3.Close()
	if e!=nil { err = e; return }
	e = enc2.Close()
	if e!=nil { err = e; return }
	e = enc1.Close()
	if e!=nil { err = e; return }
	e = msgw.Close()
	if e!=nil { err = e; return }
	
	wrap = &qmodel.Message{
		From: orig.From,
		To: []string{remailer},
		Body: msgb.Bytes(),
	}
	return
}


