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

/*!

1. Client:

Has:

* client_pk
* client_sk
* server_pk

Computes and Stores:

* client_sent_nonce = random nonce()

Computes:

* shared_key = encrypt_precompute(server_pk, client_sk)
* (temp_client_pk, temp_client_sk) = crypto_box_keypair()

Stores:

* temp_client_sk

Computes:

* payload = [temp_client_pk, client_sent_nonce]

* nonce = random nonce()
* encrypted_payload = encrypt_data_symmetric(shared_key, nonce, payload)
* handshake_packet = [client_pk, nonce, encrypted_payload]

Sends:

* handshake_packet

By now client has:
* server_pk
* client_pk
* client_sk
* client_sent_nonce
* temp_client_sk

2. Server:

Receives:

* handshake_packet

Has:

* server_pk
* server_sk

Computes and Stores:

* server_sent_nonce = random nonce()

Computes:

* [client_pk, nonce, encrypted_payload] = handshake_packet
* shared_key = encrypt_precompute(client_pk, server_sk)
* payload = decrypt_data_symmetric(shared_key, nonce, encrypted_payload)

* [temp_client_pk, server_recv_nonce=client_sent_nonce] = payload

* (temp_server_pk, temp_server_sk) = crypto_box_keypair()
* common_shared_key = encrypt_precompute(temp_client_pk, temp_server_sk)

Stores:

* server_recv_nonce
* common_shared_key
* client_pk

Computes:

* payload = [temp_server_pk, server_sent_nonce]
* nonce = random nonce()
* encrypted_payload = encrypt_data_symmetric(shared_key, nonce, payload)

* handshake_packet = [nonce, encrypted_payload]

Sends:

* handshake_packet


By now server has:

* client_pk
* server_pk
* server_sk
* server_sent_nonce
* server_recv_nonce
* common_shared_key

3. Client:

Receives:

* handshake_packet

Computes:

* shared_key = encrypt_precompute(server_pk, client_sk)
* [nonce, encrypted_payload] = handshake_packet
* payload = decrypt_data_symmetric(shared_key, nonce, encrypted_payload)

* [temp_server_pk, client_recv_nonce=server_sent_nonce] = payload

* common_shared_key = encrypt_precompute(temp_server_pk, temp_client_sk)


Stores:

* client_recv_nonce
* common_shared_key

Removes:

* temp_client_sk

By now client has:
* server_pk
* client_pk
* client_sk
* client_sent_nonce
* client_recv_nonce
* common_shared_key


*/

/** The response of the server to a TCP handshake.

Serialized form:

Length  | Contents
------- | --------
`32`    | PK of the client
`24`    | Nonce for the encrypted data
`72`    | Encrypted payload (plus MAC)

*/

use toxcore::crypto_core::*;
use toxcore::binary_io::*;

struct Client {
    pk: PublicKey,
    nonce: Nonce,
    payload: Vec<u8>
}

nom_from_bytes!(Client, do_parse!(
    pk: call!(PublicKey::nom_parse_bytes) >>
    nonce: call!(Nonce::nom_parse_bytes) >>
    payload: take!(72) >>
    (Client { pk: pk, nonce: nonce, payload: payload.to_vec() })
));

to_bytes!(Client, result, self {
    result.extend_from_slice(self.pk.as_ref());
    result.extend_from_slice(self.nonce.as_ref());
    result.extend_from_slice(self.payload.as_ref());
});

/** The response of the server to a TCP handshake.

Serialized form:

Length  | Contents
------- | --------
`24`    | Nonce for the encrypted data
`72`    | Encrypted payload (plus MAC)

*/

struct Server {
    nonce: Nonce,
    payload: Vec<u8>
}

nom_from_bytes!(Server, do_parse!(
    nonce: call!(Nonce::nom_parse_bytes) >>
    payload: take!(72) >>
    (Server { nonce: nonce, payload: payload.to_vec() })
));

to_bytes!(Server, result, self {
    result.extend_from_slice(self.nonce.as_ref());
    result.extend_from_slice(self.payload.as_ref());
});

/** The payload of a TCP handshake. The payload is encrypted with algo:

shared_key = encrypt_precompute(self_pk, other_sk)
encrypted_payload = encrypt_data_symmetric(shared_key, nonce, payload)



Serialized and decrypted form:

Length  | Contents
------- | --------
`32`    | PublicKey for the current session
`24`    | Nonce of the current session

*/

struct Payload {
    session_pk: PublicKey,
    session_nonce: Nonce
}

nom_from_bytes!(Payload, do_parse!(
    pk: call!(PublicKey::nom_parse_bytes) >>
    nonce: call!(Nonce::nom_parse_bytes) >>
    (Payload { session_pk: pk, session_nonce: nonce })
));

to_bytes!(Payload, result, self {
    result.extend_from_slice(self.session_pk.as_ref());
    result.extend_from_slice(self.session_nonce.as_ref());
});
