#!/usr/bin/env python3

# This file is part of the Trezor project.
#
# Copyright (C) 2012-2022 Onekey and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from typing import TYPE_CHECKING, Union, cast

from . import messages
from .tools import expect

if TYPE_CHECKING:
    from .client import TrezorClient
    from .tools import Address
    from .protobuf import MessageType


@expect(messages.AlephiumAddress)
def get_address(
    client: "TrezorClient",
    address_n: "Address",
    show_display: bool = False,
    include_public_key: bool = False,
    target_group: Union[int, None] = None,
) -> "MessageType":
    res = client.call(
        messages.AlephiumGetAddress(
            address_n=address_n,
            show_display=show_display,
            include_public_key=include_public_key,
            target_group=target_group,
        )
    )
    return res


@expect(messages.AlephiumSignedTx)
def sign_tx(
    client: "TrezorClient", address_n: "Address", rawtx: str, data_length: int
) -> "MessageType":
    rawtx_bytes = bytes.fromhex(rawtx)
    print("AlephiumTxRequest start 0000")
    try:
        resp = client.call(
            messages.AlephiumSignTx(
                address_n=address_n,
                data_initial_chunk=rawtx_bytes,
                data_length=data_length,
            )
        )
    except Exception as e:
        print(f"Error during initial call: {e}")
        raise

    if isinstance(resp, messages.AlephiumSignedTx):
        return cast("MessageType", resp)
    else:
        print(f"Unexpected response type: {type(resp)}")
        raise ValueError("Unexpected response type")


@expect(messages.AlephiumMessageSignature)
def sign_message(
    client: "TrezorClient", address_n: "Address", message: str, message_type: str
):
    message_bytes = message.encode("utf-8")
    message_type_bytes = message_type.encode("utf-8")
    resp = client.call(
        messages.AlephiumSignMessage(
            address_n=address_n, message=message_bytes, message_type=message_type_bytes
        )
    )
    return resp
