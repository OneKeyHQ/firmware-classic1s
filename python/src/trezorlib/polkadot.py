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

from . import messages
from .tools import expect

if TYPE_CHECKING:
    from .client import TrezorClient
    from .tools import Address
    from .protobuf import MessageType

DEFAULT_BIP32_PATH = "m/44h/354h/0h/0h/0h"


# ====== Client functions ====== #


@expect(messages.PolkadotAddress)
def get_address(
    client: "TrezorClient",
    address_n: "Address",
    prefix: int,
    network: str,
    show_display: bool = False,
) -> "MessageType":
    return client.call(
        messages.PolkadotGetAddress(
            address_n=address_n,
            prefix=prefix,
            network=network,
            show_display=show_display,
        )
    )


@expect(messages.PolkadotSignedTx)
def sign_tx(client: "TrezorClient", address_n: "Address", rawtx: bytes, network: str):
    return client.call(
        messages.PolkadotSignTx(address_n=address_n, raw_tx=rawtx, network=network)
    )
