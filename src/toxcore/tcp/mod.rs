/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2017 Zetok Zalbavar <zexavexxe@gmail.com>
    Copyright © 2017 Roman Proskuryakov <humbug@deeptown.org>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

use toxcore::crypto_core::*;
use toxcore::binary_io::*;

pub mod handshake;
pub mod packet;


// TODO remove
nom_from_bytes!(PublicKey, map_opt!(take!(PUBLICKEYBYTES), PublicKey::from_slice));
nom_from_bytes!(Nonce, map_opt!(take!(NONCEBYTES), Nonce::from_slice));
