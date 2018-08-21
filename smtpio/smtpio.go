/*
  Copyright (C) 2018 Simon Schmidt

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

// Smtp Input and Output
package smtpio

import "github.com/emersion/go-smtp"
import "github.com/emersion/go-sasl"

//import "github.com/a-mail-group/ampp/qmodel"
import "github.com/a-mail-group/ampp/queue"
import "io"
import "bytes"
import "crypto/tls"

type Input struct{
	Q *queue.Queue
	N string
}
func (i *Input) Send(from string, to []string, r io.Reader) error{
	var err1 error
	err2 := i.Q.Process(func(tx *queue.Tx) error {
		err1 = tx.Enqueue(i.N,from,to,r)
		return nil
	})
	if err1==nil { err1 = err2 }
	return err1
}
func (i *Input) Logout() error { return nil }

var _ smtp.User = (*Input)(nil)

type Output struct{
	Q *queue.Queue
	N string
}

func (i *Output) ProcessSimple(addr string, a sasl.Client) error {
	return i.Q.Process(func(tx *queue.Tx) error {
		f := tx.Fetch(i.N)
		keys := make([][]byte,1024)
		for {
			k,m,e := f.Next()
			if e==io.EOF { break }
			if e!=nil { keys = append(keys,k); continue } // XXX ignores broken messages.
			e = smtp.SendMail(addr,a,m.From,m.To,bytes.NewReader(m.Body))
			if e!=nil { break } // Network errors.
			keys = append(keys,k)
			if len(keys)>=1024 {
				tx.RemoveAll(i.N,keys) // XXX ignore errors!
				keys = keys[:0]
			}
		}
		tx.RemoveAll(i.N,keys) // XXX ignore errors!
		return nil
	})
}

func (i *Output) ProcessFast(hostname string,addr string, a sasl.Client) error {
	c,err := smtp.Dial(addr)
	if err!=nil { return err }
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: hostname}
		if err = c.StartTLS(config); err != nil {
			return err
		}
	}
	if ok, _ := c.Extension("AUTH"); ok && a!=nil {
		if err = c.Auth(a); err != nil {
			return err
		}
	}
	return i.Q.Process(func(tx *queue.Tx) error {
		f := tx.Fetch(i.N)
		keys := make([][]byte,1024)
		for {
			k,m,e := f.Next()
			if e==io.EOF { break }
			if e!=nil { keys = append(keys,k); continue } // XXX ignores broken messages.
			e = c.Mail(m.From)
			if e!=nil { break }
			for _,to := range m.To {
				e = c.Rcpt(to)
				if e!=nil { break }
			}
			w,e := c.Data()
			if e!=nil { break }
			_,e = w.Write(m.Body)
			if e!=nil { break }
			e = w.Close()
			if e!=nil { break }
			keys = append(keys,k)
			if len(keys)>=1024 {
				tx.RemoveAll(i.N,keys) // XXX ignore errors!
				keys = keys[:0]
			}
		}
		tx.RemoveAll(i.N,keys) // XXX ignore errors!
		c.Quit()
		return nil
	})
}

