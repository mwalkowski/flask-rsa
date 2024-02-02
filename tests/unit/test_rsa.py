from unittest.mock import MagicMock

from flask_rsa import RSA


class FlaskAppStub:

    def __init__(self):
        self.name = 'FlaskAppStub'
        self.debug = True
        self.config = {}

    def add_url_rule(self, *args, **kwargs):
        pass


def test_default_signature_header():
    stub = FlaskAppStub()
    request_mock = MagicMock()
    request_mock.headers.get.return_value = 'A'

    uut = RSA(stub)
    uut.verify = MagicMock(uut.verify)

    uut.is_signature_correct(request_mock)

    assert request_mock.headers.__get__.assert_called_once_with('X-Signature')


def test_signature_header_config():
    stub = FlaskAppStub()
    stub.config['RSA_SIGNATURE_HEADER'] = 'X-Signature-2'

    #uut = RSA(stub)

