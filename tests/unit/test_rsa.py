import pytest

from unittest.mock import MagicMock
from flask_rsa import RSA


class FlaskAppStub:

    def __init__(self):
        self.name = 'FlaskAppStub'
        self.debug = True
        self.config = {}

    def add_url_rule(self, *args, **kwargs):
        pass


@pytest.mark.parametrize("header", ["X-Signature", "X-Nonce-Value", "X-Nonce-Created-At"])
def test_default_header(header):
    stub = FlaskAppStub()
    request_mock = MagicMock()
    request_mock.headers.get.return_value = 'A'

    uut = RSA(stub)
    uut.verify = MagicMock(uut.verify)

    uut.is_signature_correct(request_mock)

    request_mock.headers.__getitem__.assert_any_call(header)


@pytest.mark.parametrize("config,header", [
    ("RSA_SIGNATURE_HEADER", "X-Signature-1"),
    ("RSA_NONCE_HEADER", "X-Nonce-Value-1"),
    ("RSA_NONCE_CREATED_AT_HEADER", "X-Nonce-Created-A-1")])
def test_header_config(config, header):
    stub = FlaskAppStub()
    request_mock = MagicMock()
    request_mock.headers.get.return_value = 'A'
    stub.config[config] = header

    uut = RSA(stub)
    uut.verify = MagicMock(uut.verify)

    uut.is_signature_correct(request_mock)

    request_mock.headers.__getitem__.assert_any_call(header)
