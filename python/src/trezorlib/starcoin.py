# This file is part of the OneKey project, https://onekey.so/
#
# Copyright (C) 2021 OneKey Team <core@onekey.so>
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.


from typing import TYPE_CHECKING

from . import exceptions, messages
from .tools import expect

if TYPE_CHECKING:
    from .client import TrezorClient
    from .tools import Address
    from .protobuf import MessageType

DEFAULT_BIP32_PATH = "m/44h/101010h/0h/0h/0h"


# ====== Client functions ====== #


@expect(messages.StarcoinAddress, field="address", ret_type=str)
def get_address(
    client: "TrezorClient", address_n: "Address", show_display: bool = False
) -> "MessageType":
    return client.call(
        messages.StarcoinGetAddress(address_n=address_n, show_display=show_display)
    )


@expect(messages.StarcoinPublicKey)
def get_public_key(
    client: "TrezorClient", n: "Address", show_display: bool = False
) -> "MessageType":
    return client.call(
        messages.StarcoinGetPublicKey(address_n=n, show_display=show_display)
    )


@expect(messages.StarcoinSignedTx)
def sign_tx(client: "TrezorClient", address_n: "Address", rawtx: bytes):
    return client.call(messages.StarcoinSignTx(address_n=address_n, raw_tx=rawtx))


@expect(messages.StarcoinMessageSignature)
def sign_message(client: "TrezorClient", n: "Address", message: bytes):
    return client.call(messages.StarcoinSignMessage(address_n=n, message=message))


def verify_message(
    client: "TrezorClient", pubkey: bytes, signature: bytes, message: bytes
):
    try:
        resp = client.call(
            messages.StarcoinVerifyMessage(
                signature=signature, public_key=pubkey, message=message
            )
        )
    except exceptions.TrezorFailure:
        return False
    return isinstance(resp, messages.Success)
