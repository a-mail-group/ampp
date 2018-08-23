/*
  Copyright (C) 2018 Simon Schmidt

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/


package handler

import "github.com/a-mail-group/ampp/qmodel"

type IQueue interface{
	EnqueueMessage(queue string,msg *qmodel.Message) error
}

