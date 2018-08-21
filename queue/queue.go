/*
  Copyright (C) 2018 Simon Schmidt

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

// Mail-Queue backed by BoltDB
package queue


import bolt "github.com/coreos/bbolt"
import smtp "github.com/emersion/go-smtp"
import "github.com/vmihailenco/msgpack"
import "io/ioutil"
import "io"
import "time"

import "github.com/a-mail-group/ampp/qmodel"

type Queue struct{
	DB *bolt.DB
}
func Open(name string) (*Queue,error) {
	db,err := bolt.Open(name,0600,nil)
	if err!=nil { return nil,err }
	return &Queue{db},nil
}
func (q *Queue) Close() error { return q.DB.Close() }
func (q *Queue) Process(f func(*Tx) error) error {
	return q.DB.Batch(func(tx *bolt.Tx) error { return f(&Tx{tx}) })
}

type Tx struct{
	tx *bolt.Tx
}
func (tx *Tx) EnqueueMessage(queue string,msg *qmodel.Message) error {
	key := make([]byte,0,len(time.RFC3339Nano))
	key = time.Now().UTC().AppendFormat(key,time.RFC3339Nano)
	return tx.ReEnqueueMessage(key,queue,msg)
}
func (tx *Tx) ReEnqueueMessage(key []byte,queue string,msg *qmodel.Message) error {
	data,err := msgpack.Marshal(msg)
	if err!=nil { return err }
	bkt,err := tx.tx.CreateBucketIfNotExists([]byte(queue))
	if err!=nil { return err }
	
	return bkt.Put(key,data)
}

func (tx *Tx) DequeueMessage(queue string) (key []byte,msg *qmodel.Message,err error) {
	bkt := tx.tx.Bucket([]byte(queue))
	if bkt==nil { err = io.EOF; return }
	k,v := bkt.Cursor().First()
	if len(k)==0 { err = io.EOF; return }
	msg = new(qmodel.Message)
	err = msgpack.Unmarshal(v,msg)
	if err!=nil { msg = nil; return }
	key = make([]byte,len(k))
	copy(key,k)
	return
}
func (tx *Tx) Enqueue(queue string,from string, to []string, r io.Reader) error {
	data,err := ioutil.ReadAll(r)
	if err!=nil { return err }
	if len(data) > 3<<9 { return smtp.ErrDataTooLarge }
	return tx.EnqueueMessage(queue,&qmodel.Message{from,to,data})
}

