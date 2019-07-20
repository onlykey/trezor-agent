"""TREZOR support for Ed25519 signify signatures."""

import argparse
import binascii
import contextlib
import functools
import hashlib
import logging
import os
import re
import subprocess
import sys
import time

import pkg_resources
import semver


from .. import formats, server, util
from ..device import interface, ui

log = logging.getLogger(__name__)


def _create_identity(user_id):
    result = interface.Identity(identity_str='signify://', curve_name='ed25519')
    result.identity_dict['host'] = user_id
    return result


class Client:
    """Sign messages and get public keys from a hardware device."""

    def __init__(self, device):
        """C-tor."""
        self.device = device

    def pubkey(self, identity):
        """Return public key as VerifyingKey object."""
        with self.device:
            pubkey = self.device.pubkey(ecdh=False, identity=identity)
        assert len(pubkey) == 33
        assert pubkey[:1] == b'\x00'
        return pubkey[1:]

    def sign(self, identity, data):
        """Sign the data and return a signature."""
        log.info('please confirm Signify signature on %s for "%s"...',
                 self.device, identity.to_string())
        log.debug('signing data: %s', util.hexlify(data))
        with self.device:
            sig = self.device.sign(blob=data, identity=identity)
            assert len(sig) == 64
            return sig


def run_init(device_type, args):
    """Initialize hardware-based Signify identity."""
    util.setup_logging(verbosity=args.verbose)
    log.warning('This Signify tool is still in EXPERIMENTAL mode, '
                'so please note that the key derivation, API, and features '
                'may change without backwards compatibility!')

    identity = _create_identity(user_id=args.user_id)
    pubkey = Client(device=device_type()).pubkey(identity=identity)
    pkalg = b'Ed'
    keynum = b'\x00' * 8
    comment = 'untrusted comment: TREZOR {} signify public key\n'.format(identity.to_string())
    result = comment.encode('ascii') + binascii.b2a_base64(pkalg + keynum + pubkey)
    with open(args.user_id + '.pub', 'wb') as f:
        f.write(result)


def run_sign(device_type, args):
    """Sign given file using Ed25519 (for Signify)."""
    util.setup_logging(verbosity=args.verbose)
    identity = _create_identity(user_id=args.user_id)
    data = open(args.message, 'rb').read()
    sig = Client(device=device_type()).sign(identity, data)
    pkalg = b'Ed'
    keynum = b'\x00' * 8
    comment = 'untrusted comment: signed with TREZOR {}\n'.format(identity.to_string())
    result = comment.encode('ascii') + binascii.b2a_base64(pkalg + keynum + sig)
    with open(args.message + '.sig', 'wb') as f:
        f.write(result)


def run_unlock(device_type, args):
    """Unlock hardware device (for future interaction)."""
    util.setup_logging(verbosity=args.verbose)
    with device_type() as d:
        log.info('unlocked %s device', d)


def main(device_type):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(title='Action', dest='action')
    subparsers.required = True

    p = subparsers.add_parser('init')
    p.add_argument('user_id')
    p.add_argument('-v', '--verbose', default=0, action='count')
    p.set_defaults(func=run_init)

    p = subparsers.add_parser('sign')
    p.add_argument('user_id')
    p.add_argument('-v', '--verbose', default=0, action='count')
    p.add_argument('-m', '--message')
    p.set_defaults(func=run_sign)

    p = subparsers.add_parser('unlock', help='unlock the hardware device')
    p.add_argument('-v', '--verbose', default=0, action='count')
    p.set_defaults(func=run_unlock)

    args = parser.parse_args()
    device_type.ui = ui.UI(device_type=device_type, config=vars(args))
    device_type.ui.cached_passphrase_ack = util.ExpiringCache(seconds=float(60))

    return args.func(device_type=device_type, args=args)
