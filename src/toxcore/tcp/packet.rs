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

// FIXME all connection_id from_bytes must be connection_id -16
// FIXME all connection_id to_bytes must be connection_id +16

use toxcore::crypto_core::*;
use toxcore::binary_io::*;
use toxcore::common_parsers::*;
use nom::*;
use byteorder::{BigEndian, LittleEndian, WriteBytesExt};


/** Top-level TCP packet kind names and their associated numbers.

    According to https://zetok.github.io/tox-spec/#encrypted-payload-types.
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// [`RouteRequest`](./struct.RouteRequest.html) packet id.
    RouteRequest  = 0,
    /// [`RouteResponse`](./struct.RouteResponse.html) packet id.
    RouteResponse = 1,
    /// [`ConnectNotification`](./struct.ConnectNotification.html) packet id.
    ConnectNotification = 2,
    /// [`DisconnectNotification`](./struct.DisconnectNotification.html) packet id.
    DisconnectNotification = 3,
    /// [`PingRequest`](./struct.PingRequest.html) packet id.
    PingRequest = 4,
    /// [`PongResponse`](./struct.PongResponse.html) packet id.
    PongResponse = 5,
    /// [`OobSend`](./struct.OobSend.html) packet id.
    OobSend = 6,
    /// [`OobReceive`](./struct.OobReceive.html) packet id.
    OobReceive = 7,
    /// TODO
    OnionDataRequest = 8,
    /// TODO
    OnionDataResponse = 9,
    /// Data
    Data
}

nom_from_bytes!(Kind, map_opt!(ne_u8, |byte| {
    // TODO 16 = NUM_RESERVED_PORTS, 256 = NUM_CLIENT_CONNECTIONS = (256 - NUM_RESERVED_PORTS)
    if byte >= 16 && byte < 240 {
        return Some(Kind::Data)
    }
    match byte {
        0 => Some(Kind::RouteRequest),
        1 => Some(Kind::RouteResponse),
        2 => Some(Kind::ConnectNotification),
        3 => Some(Kind::DisconnectNotification),
        4 => Some(Kind::PingRequest),
        5 => Some(Kind::PongResponse),
        6 => Some(Kind::OobSend),
        7 => Some(Kind::OobReceive),
        8 => Some(Kind::OnionDataRequest),
        9 => Some(Kind::OnionDataResponse),
        _ => None
    }
}));

/// Trait for types of TCP packets that can be put in [`TcpPacket`]
/// (./struct.TcpPacket.html).
pub trait TcpPacketable: ToBytes + NomFromBytes {
    /// Provide packet type id.
    ///
    /// To use for serialization: `.kind() as u8`.
    fn kind(&self) -> Kind;
}

macro_rules! tcp_packet (
    ($name:ident) => {
        impl TcpPacketable for $name {
            fn kind(&self) -> Kind {
                Kind::$name
            }
        }
    }
);

/** Standard TCP packet that encapsulates in the encrypted payload
[`TcpPacketable`](./trait.TcpPacketable.html).

Length      | Contents
----------- | --------
`2`         | Lenght in BigEndian
variable    | Encrypted payload

https://zetok.github.io/tox-spec/#tcp-server

*/
pub struct TcpPacket {
    /// The type of the packet
    packet_type: Kind,
    /// Encrypted payload
    payload: Vec<u8>,
}

impl TcpPacket {
    /// Create new `TcpPacket` with encrypted `payload`.
    pub fn new<P>(packet: &P) -> Self
        where P: TcpPacketable
    {
        // FIXME encrypt data
        let payload = TcpPacket::encrypt( packet );

        TcpPacket {
            packet_type: packet.kind(),
            payload: payload,
        }
    }

    /** Get [`Kind`](./enum.Kind.html) that
    `TcpPacket`'s payload is supposed to contain.
    */
    pub fn kind(&self) -> Kind {
        self.packet_type
    }

    /**
    Get packet data. This function decrypts payload and tries to parse it
    as packet type.

    To get info about it's packet type use
    [`.kind()`](./struct.TcpPacket.html#method.kind).

    Returns `None` in case of faliure:

    - fails to decrypt
    - fails to parse as given packet type
    */
    pub fn extract<P>(&self) -> Option<P>
        where P: TcpPacketable
    {
        // FIXME decrypt data
        let decrypted = TcpPacket::decrypt( &self.payload );
        P::nom_from_bytes(&decrypted)
    }

    // FIXME
    fn encrypt<P>(packet: &P) -> Vec<u8>
        where P: TcpPacketable
    {
        unimplemented!();
        packet.to_bytes()
    }

    // FIXME
    fn decrypt(payload: &Vec<u8>) -> Vec<u8>
    {
        unimplemented!();
        payload.clone()
    }
}

nom_from_bytes!(TcpPacket, do_parse!(
    length: be_u16 >>
    payload: take!(length) >>
    // FIXME we have to decrypt data to get packet_type
    (TcpPacket { packet_type: Kind::RouteRequest, payload: payload.to_vec() })
));

to_bytes!(TcpPacket, result, self {
    // FIXME check payload.len <= 2^16
    result.write_u16::<BigEndian>(self.payload.len() as u16).expect("Failed to write length!");
    result.extend_from_slice(&self.payload);
});


/** Sent by client to server.
Send a routing request to the server that we want to connect
to peer with public key where the public key is the public the peer
announced themselves as. The server must respond to this with a `RouteResponse`.

Packet type [`Kind::RouteRequest`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x00
`32`   | DHT Public Key

*/
pub struct RouteRequest {
    /// The requested PK
    pub peer_pk: PublicKey,
}

tcp_packet!(RouteRequest);

nom_from_bytes!(RouteRequest, do_parse!(
    peer_pk: call!(PublicKey::nom_parse_bytes) >>
    (RouteRequest { peer_pk })
));

to_bytes!(RouteRequest, result, self {
    result.extend_from_slice(self.peer_pk.as_ref());
});

/** Sent by server to client.
The response to the routing request, tell the client if the
routing request succeeded (valid `connection_id`) and if it did,
tell them the id of the connection (`connection_id`). The public
key sent in the routing request is also sent in the response so
that the client can send many requests at the same time to the
server without having code to track which response belongs to which public key.

Packet type [`Kind::RouteResponse`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x01
`1`    | connection_id
`32`   | DHT Public Key

*/
pub struct RouteResponse {
    /// The id of the requested PK
    pub connection_id: u8,
    /// The requested PK
    pub pk: PublicKey,
}

tcp_packet!(RouteResponse);

nom_from_bytes!(RouteResponse, do_parse!(
    connection_id: be_u8 >>
    pk: call!(PublicKey::nom_parse_bytes) >>
    (RouteResponse { connection_id, pk })
));

to_bytes!(RouteResponse, result, self {
    result.push(self.connection_id);
    result.extend_from_slice(self.pk.as_ref());
});

/** Sent by server to client.
Tell the client that connection_id is now connected meaning the other
is online and data can be sent using this `connection_id`.

Packet type [`Kind::ConnectNotification`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x02
`1`    | connection_id

*/
pub struct ConnectNotification {
    /// The id of the connected client
    pub connection_id: u8
}

tcp_packet!(ConnectNotification);

nom_from_bytes!(ConnectNotification, do_parse!(
    connection_id: be_u8 >>
    (ConnectNotification { connection_id })
));

to_bytes!(ConnectNotification, result, self {
    result.push(self.connection_id);
});

/** Sent by client to server.
Sent when client wants the server to forget about the connection related
to the connection_id in the notification. Server must remove this connection
and must be able to reuse the `connection_id` for another connection. If the
connection was connected the server must send a disconnect notification to the
other client. The other client must think that this client has simply
disconnected from the TCP server.

Sent by server to client.
Sent by the server to the client to tell them that the connection with
`connection_id` that was connected is now disconnected. It is sent either
when the other client of the connection disconnect or when they tell the
server to kill the connection (see above).

Packet type [`Kind::DisconnectNotification`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x03
`1`    | connection_id

*/
pub struct DisconnectNotification {
    /// The id of the disconnected client
    pub connection_id: u8
}

tcp_packet!(DisconnectNotification);

nom_from_bytes!(DisconnectNotification, do_parse!(
    connection_id: be_u8 >>
    (DisconnectNotification { connection_id })
));

to_bytes!(DisconnectNotification, result, self {
    result.write_u8(self.connection_id).expect("Failed to write connection_id!");
});

/** Sent by both client and server, both will respond.
Ping packets are used to know if the other side of the connection is still
live. TCP when established doesn't have any sane timeouts (1 week isn't sane)
so we are obliged to have our own way to check if the other side is still live.
Ping ids can be anything except 0, this is because of how toxcore sets the
variable storing the `ping_id` that was sent to 0 when it receives a pong
response which means 0 is invalid.

The server should send ping packets every X seconds (toxcore `TCP_server` sends
them every 30 seconds and times out the peer if it doesn't get a response in 10).
The server should respond immediately to ping packets with pong packets.


Packet type [`Kind::PingRequest`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x04
`8`    | ping_id in LittleEndian

*/
pub struct PingRequest {
    /// The id of ping
    pub ping_id: u64
}

tcp_packet!(PingRequest);

nom_from_bytes!(PingRequest, do_parse!(
    ping_id: le_u64 >>
    (PingRequest { ping_id })
));

to_bytes!(PingRequest, result, self {
    result.write_u64::<LittleEndian>(self.ping_id).expect("Failed to write ping_id!");
});

/** Sent by both client and server, both will respond.
The server should respond to ping packets with pong packets with the same `ping_id`
as was in the ping packet. The server should check that each pong packet contains
the same `ping_id` as was in the ping, if not the pong packet must be ignored.

Packet type [`Kind::PongResponse`](./enum.Kind.html).

Serialized form:

Length | Content
------ | ------
`1`    | 0x05
`8`    | ping_id in LittleEndian

*/
pub struct PongResponse {
    /// The id of ping to respond
    pub ping_id: u64
}

tcp_packet!(PongResponse);

nom_from_bytes!(PongResponse, do_parse!(
    ping_id: le_u64 >>
    (PongResponse { ping_id })
));

to_bytes!(PongResponse, result, self {
    result.write_u64::<LittleEndian>(self.ping_id).expect("Failed to write ping_id!");
});

/** Sent by client to server.
If a peer with private key equal to the key they announced themselves with is
connected, the data in the OOB send packet will be sent to that peer as an
OOB recv packet. If no such peer is connected, the packet is discarded. The
toxcore `TCP_server` implementation has a hard maximum OOB data length of 1024.
1024 was picked because it is big enough for the `net_crypto` packets related
to the handshake and is large enough that any changes to the protocol would not
require breaking `TCP server`. It is however not large enough for the bigges
`net_crypto` packets sent with an established `net_crypto` connection to
prevent sending those via OOB packets.

OOB packets can be used just like normal data packets however the extra size
makes sending data only through them less efficient than data packets.

Packet type [`Kind::OobSend`](./enum.Kind.html).

Serialized form:

Length   | Content
-------- | ------
`1`      | 0x06
`32`     | DHT Public Key
variable | Data

*/
pub struct OobSend {
    /// Public Key of the receiver
    pub destination_pk: PublicKey,
    /// OOB data packet
    pub data: Vec<u8>
}

tcp_packet!(OobSend);

nom_from_bytes!(OobSend, do_parse!(
    destination_pk: call!(PublicKey::nom_parse_bytes) >>
    // FIXME check data lenght
    data: map!(rest, |bytes| bytes.to_vec() ) >>
    (OobSend { destination_pk, data })
));

to_bytes!(OobSend, result, self {
    result.extend_from_slice(self.destination_pk.as_ref());
    result.extend_from_slice(&self.data);
});

/** Sent by server to client.
OOB recv are sent with the announced public key of the peer that sent the
OOB send packet and the exact data.

Packet type [`Kind::OobSend`](./enum.Kind.html).

Serialized form:

Length   | Content
-------- | ------
`1`      | 0x07
`32`     | DHT Public Key
variable | Data

*/
pub struct OobReceive {
    /// Public Key of the sender
    pub sender_pk: PublicKey,
    /// OOB data packet
    pub data: Vec<u8>
}

tcp_packet!(OobReceive);

nom_from_bytes!(OobReceive, do_parse!(
    sender_pk: call!(PublicKey::nom_parse_bytes) >>
    // FIXME check data lenght
    data: map!(rest, |bytes| bytes.to_vec() ) >>
    (OobReceive { sender_pk, data })
));

to_bytes!(OobReceive, result, self {
    result.extend_from_slice(&self.sender_pk.as_ref());
    result.extend_from_slice(&self.data);
});

/** Sent by client to server.
The client sends data with `connection_id` and the server
relays it to the given connection

Packet type [`Kind::Data`](./enum.Kind.html).

Serialized form:

Length   | Content
-------- | ------
`1`      | connection_id [ 0x10 .. 0xF0 )
variable | Data

*/
pub struct Data {
    /// The id of the connection of the client
    pub connection_id: u8,
    /// Data packet
    pub data: Vec<u8>
}

tcp_packet!(Data);

nom_from_bytes!(Data, do_parse!(
    connection_id: be_u8 >>
    data: map!(rest, |bytes| bytes.to_vec() ) >>
    (Data { connection_id, data })
));

to_bytes!(Data, result, self {
    result.push(self.connection_id);
    result.extend_from_slice(&self.data);
});
