from copy import copy
from cryptography.exceptions import InvalidTag
import pytest

from pycose.keys import EC2Key
from pycose.keys.curves import P256, P384, P521
from pycose.messages import Enc0Message
from pycose.headers import Algorithm, KID, HpkeEk
from pycose.algorithms import HPKE_0, HPKE_1, HPKE_2

from .test_ec2_keys import (
    p256_x, p256_y, p256_d,
    p384_x, p384_y, p384_d,
    p521_x, p521_y, p521_d,
)

_PRIV = {
    P256: EC2Key(crv=P256, x=p256_x, y=p256_y, d=p256_d),
    P384: EC2Key(crv=P384, x=p384_x, y=p384_y, d=p384_d),
    P521: EC2Key(crv=P521, x=p521_x, y=p521_y, d=p521_d),
}
""" Same keys as other test fixture """

_PUB = {crv: EC2Key(crv=crv, x=other.x, y=other.y) for crv, other in _PRIV.items()}

@pytest.mark.parametrize('aad_diff', [False, True])
@pytest.mark.parametrize('crv,alg', [
    (P256, HPKE_0),
    (P384, HPKE_1),
    (P521, HPKE_2),
])
def test_hpke_encrypt0_roundtrip(crv, alg, aad_diff):
    priv = _PRIV[crv]
    pub = _PUB[crv]

    plaintext = b'hello'

    msg_out = Enc0Message(
        phdr={
            Algorithm: alg,
        },
        uhdr={
        },
        payload=copy(plaintext),
        external_aad=b'AAD',
        key=pub
    )
    assert isinstance(msg_out.encrypt(), bytes)
    msg_enc = msg_out.encode()
    assert isinstance(msg_enc, bytes)

    msg_in = Enc0Message.decode(msg_enc)
    assert isinstance(msg_in, Enc0Message)
    assert msg_in.payload != plaintext
    msg_in.key = priv
    msg_in.external_aad = b'other' if aad_diff else b'AAD'
    if aad_diff:
        with pytest.raises(InvalidTag):
            plain = msg_in.decrypt()
    else:
        plain = msg_in.decrypt()
        assert plain.hex() == plaintext.hex()

def test_hpke_example_5_1_decode():
    priv = EC2Key.from_dict({
         1: 2,
         2: bytes.fromhex('626f62'),
         3: HPKE_0.identifier,
        -1: P256.identifier,
        -2: bytes.fromhex('02a8e3315f96bc7355dbf85740c6d8e53fb070cd8ba5c419be49a91d789ef55c'),
        -3: bytes.fromhex('96b6621abf5ca532e042dc5c346c1ef0c9186b83cb122e50a46f1458de023d35'),
        -4: bytes.fromhex('eca39300147c91a2a65d17e00ea278b57a14178245bf5686d9a404cca1816b8e'),
    })

    expect_payload=b'This is the content.'

    msg_enc = bytes.fromhex(
        'd08344a1011823a20443626f622358410457229bdd99407b384a9e59fa15'
        '53224d58b106e9ebebdaa06d2126bd96757674847669966ecb0dcdf21af5'
        '623f19f0b799b0cddf3ee930b739dd474f6282de0158253f3c1595e9d252'
        'e816215a9ce73f47ba4b57acb06ecc39ca5a03a14108bbe7807af5688d61'
    )

    msg_in = Enc0Message.decode(msg_enc)
    assert isinstance(msg_in, Enc0Message)
    assert msg_in.get_attr(Algorithm) == HPKE_0
    assert msg_in.get_attr(KID) == priv.kid
    assert msg_in.get_attr(HpkeEk) == bytes.fromhex(
        '0457229BDD99407B384A9E59FA1553224D58B106E9EBEBDA'
        'A06D2126BD96757674847669966ECB0DCDF21AF5623F19F0B799B0'
        'CDDF3EE930B739DD474F6282DE01'
    )
    assert msg_in.payload != expect_payload

    msg_in.key = priv
    msg_in.external_aad = b'hi'
    plain = msg_in.decrypt()
    assert isinstance(plain, bytes)
    assert plain.hex() == expect_payload.hex()
