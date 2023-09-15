/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! General purpose message-related types

use crate::types::DerSequence;

/// TODO: fields not needed now are not implemented yet
pub type GeneralInfo = DerSequence<'static>;
