/*
  Copyright (C) 2018 Simon Schmidt

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/


package handler

import "github.com/a-mail-group/ampp/remailer/cypherpunk"
import "golang.org/x/crypto/openpgp"
import "github.com/emersion/go-imap"
import "github.com/emersion/go-imap/client"
import "io/ioutil"
import "github.com/emersion/go-message"
import pgperrs "golang.org/x/crypto/openpgp/errors"

type ImapWaiter struct{
	Conn *client.Client
	Ring openpgp.KeyRing
	Mailbox, Address string
	DelInv bool
	Target IQueue
	QueueName string
}
func (i *ImapWaiter) Process() error {
	mbox,err := i.Conn.Select(i.Mailbox, false)
	if err!=nil { return err }
	seqset := new(imap.SeqSet)
	seqset.AddRange(1,mbox.Messages)
	
	delset := new(imap.SeqSet)
	
	messages := make(chan *imap.Message, 1024)
	done := make(chan error, 1)
	go func() {
		done <- i.Conn.Fetch(seqset, []imap.FetchItem{imap.FetchRFC822}, messages)
	}()
	
	for msg := range messages {
		var body imap.Literal
		for k,v := range msg.Body {
			if k.FetchItem()==imap.FetchRFC822 { body = v }
		}
		if body==nil { continue }
		ent,err := message.Read(body)
		if err!=nil { continue }
		data,err := ioutil.ReadAll(ent.Body)
		if err!=nil { continue }
		qmsg,err := cypherpunk.ProcessMessage(data,i.Address,i.Ring)
		if err!=nil {
			if err==cypherpunk.ENotRemail || err==cypherpunk.EInvalidArmor || err==cypherpunk.EUnknownEncryption {
				if i.DelInv { delset.AddRange(msg.SeqNum,msg.SeqNum) }
				continue
			}
			if err==pgperrs.ErrKeyIncorrect || err==pgperrs.ErrKeyRevoked || err==pgperrs.ErrUnknownIssuer {
				if i.DelInv { delset.AddRange(msg.SeqNum,msg.SeqNum) }
				continue
			}
			switch err.(type) {
			case	pgperrs.InvalidArgumentError,
				pgperrs.SignatureError,
				pgperrs.StructuralError,
				pgperrs.UnknownPacketTypeError,
				pgperrs.UnsupportedError:
				if i.DelInv { delset.AddRange(msg.SeqNum,msg.SeqNum) }
				continue
			}
			continue
		}
		err = i.Target.EnqueueMessage(i.QueueName,qmsg)
		if err==nil {
			delset.AddRange(msg.SeqNum,msg.SeqNum)
		}
	}
	<-done
	i.Conn.Store(delset,imap.FormatFlagsOp(imap.AddFlags, true),[]interface{}{imap.SeenFlag},nil)
	i.Conn.Expunge(nil)
	return nil
}

