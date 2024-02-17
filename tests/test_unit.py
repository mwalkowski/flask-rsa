import os
import uuid
import pytest

from datetime import datetime, timezone, timedelta


from unittest.mock import MagicMock, patch
from flask_rsa import RSA


TEST_PRIVATE_KEY_PATH = os.path.join(os.getcwd(), 'private.key')
TEST_PUBLIC_KEY_PATH = os.path.join(os.getcwd(), 'public.pem')

TEST_PRIVATE_KEY_PATH_CONF = os.path.join(os.getcwd(), 'tests', 'data', 'private.key')
TEST_PUBLIC_KEY_PATH_CONF = os.path.join(os.getcwd(), 'tests', 'data', 'public.pem')


class TestRSA(RSA):

    def __init__(self, app):
        super().__init__(app)

    def is_nonce_correct(self, request):
        return self._is_nonce_correct(request)

    def get_received_nonces_queue_size(self):
        return self._received_nonces.qsize()

    def is_nonce_created_at_correct(self, request):
        return self._is_nonce_created_at_correct(request)

    def make_response(self, msg):
        return self._make_response(msg)

    def read_public_key(self, filename):
        return self._read_public_key(filename)


@pytest.fixture()
def flask_mock():
    flask_mock = MagicMock()
    flask_mock.name = 'FlaskAppStub'
    flask_mock.debug = True
    flask_mock.config = {}
    yield flask_mock

    os.remove(TEST_PRIVATE_KEY_PATH) if os.path.exists(TEST_PRIVATE_KEY_PATH) else None
    os.remove(TEST_PUBLIC_KEY_PATH) if os.path.exists(TEST_PUBLIC_KEY_PATH) else None


@pytest.mark.parametrize("header", ["X-Signature", "X-Nonce-Value", "X-Nonce-Created-At"])
def test_default_header(flask_mock, header):
    request_mock = MagicMock()
    request_mock.headers.__getitem__.return_value = 'A'

    uut = TestRSA(flask_mock)
    uut._verify = MagicMock(uut._verify)

    uut._is_signature_correct(request_mock)

    request_mock.headers.__getitem__.assert_any_call(header)


@pytest.mark.parametrize("config,header", [
    ("RSA_SIGNATURE_HEADER", "X-Signature-1"),
    ("RSA_NONCE_HEADER", "X-Nonce-Value-1"),
    ("RSA_NONCE_CREATED_AT_HEADER", "X-Nonce-Created-A-1")])
def test_header_config(flask_mock, config, header):
    request_mock = MagicMock()
    request_mock.headers.__getitem__.return_value = 'A'
    flask_mock.config[config] = header

    uut = TestRSA(flask_mock)
    uut._verify = MagicMock(uut._verify)

    uut._is_signature_correct(request_mock)

    request_mock.headers.__getitem__.assert_any_call(header)


def test_default_nonce_queue_limit(flask_mock):
    request_mock = MagicMock()

    uut = TestRSA(flask_mock)

    for _ in range(30):
        request_mock.headers.__getitem__.return_value = str(uuid.uuid4())
        assert uut.is_nonce_correct(request_mock)

    assert uut.get_received_nonces_queue_size() == 10


def test_config_nonce_queue_limit(flask_mock):
    request_mock = MagicMock()
    flask_mock.config["RSA_NONCE_QUEUE_SIZE_LIMIT"] = 30

    uut = TestRSA(flask_mock)

    for _ in range(60):
        request_mock.headers.__getitem__.return_value = str(uuid.uuid4())
        assert uut.is_nonce_correct(request_mock)

    assert uut.get_received_nonces_queue_size() == 30


def test_default_time_diff_tolerance_in_seconds(flask_mock):
    request_mock = MagicMock()
    uut = TestRSA(flask_mock)

    request_mock.headers.__getitem__.return_value = (
        datetime.now().astimezone(timezone.utc).isoformat())

    assert uut.is_nonce_created_at_correct(request_mock)

    created_at = datetime.now().astimezone(timezone.utc)
    created_at -= timedelta(days=0, seconds=9)

    request_mock.headers.__getitem__.return_value = created_at.isoformat()

    assert uut.is_nonce_created_at_correct(request_mock)

    created_at = datetime.now().astimezone(timezone.utc)
    created_at -= timedelta(days=0, seconds=10 + 1)

    request_mock.headers.__getitem__.return_value = created_at.isoformat()

    assert not uut.is_nonce_created_at_correct(request_mock)


def test_config_time_diff_tolerance_in_seconds(flask_mock):
    request_mock = MagicMock()
    time_diff_tolerance_in_seconds = 5
    flask_mock.config['RSA_TIME_DIFF_TOLERANCE_IN_SECONDS'] = time_diff_tolerance_in_seconds

    uut = TestRSA(flask_mock)

    request_mock.headers.__getitem__.return_value = (
        datetime.now().astimezone(timezone.utc).isoformat())

    assert uut.is_nonce_created_at_correct(request_mock)

    created_at = datetime.now().astimezone(timezone.utc)
    created_at -= timedelta(days=0, seconds=time_diff_tolerance_in_seconds - 1)

    request_mock.headers.__getitem__.return_value = created_at.isoformat()

    assert uut.is_nonce_created_at_correct(request_mock)

    created_at = datetime.now().astimezone(timezone.utc)
    created_at -= timedelta(days=0, seconds=time_diff_tolerance_in_seconds + 1)

    request_mock.headers.__getitem__.return_value = created_at.isoformat()

    assert not uut.is_nonce_created_at_correct(request_mock)


@patch('flask_rsa.flask_rsa.jsonify')
@patch('flask_rsa.flask_rsa.flask_make_response')
def test_default_error_code(flask_make_response, jsonify, flask_mock):
    uut = TestRSA(flask_mock)
    jsonify.return_value = "json msg"

    uut.make_response('test')

    jsonify.assert_called_once_with({"error": "test"})

    flask_make_response.assert_called_once_with("json msg", 403)


@patch('flask_rsa.flask_rsa.jsonify')
@patch('flask_rsa.flask_rsa.flask_make_response')
def test_config_error_code(flask_make_response, jsonify, flask_mock):
    flask_mock.config['RSA_ERROR_CODE'] = 500
    uut = TestRSA(flask_mock)

    jsonify.return_value = "json msg"

    uut.make_response('test')

    jsonify.assert_called_once_with({"error": "test"})

    flask_make_response.assert_called_once_with("json msg", 500)


def test_generate_rsa_keys(flask_mock):
    assert not os.path.isfile(TEST_PRIVATE_KEY_PATH)
    assert not os.path.isfile(TEST_PUBLIC_KEY_PATH)

    uut = TestRSA(flask_mock)
    public_key = uut.read_public_key(TEST_PUBLIC_KEY_PATH)

    assert os.path.isfile(TEST_PUBLIC_KEY_PATH)
    assert os.path.isfile(TEST_PRIVATE_KEY_PATH)

    uut = TestRSA(flask_mock)

    assert os.path.isfile(TEST_PUBLIC_KEY_PATH)
    assert os.path.isfile(TEST_PRIVATE_KEY_PATH)
    assert uut.read_public_key(TEST_PUBLIC_KEY_PATH) == public_key


def test_config_rsa_keys_nok(flask_mock):
    flask_mock.config['RSA_PRIVATE_KEY_PATH'] = 'bla'
    flask_mock.config['RSA_PUBLIC_KEY_PATH'] = TEST_PUBLIC_KEY_PATH_CONF

    with pytest.raises(FileNotFoundError):
        TestRSA(flask_mock)

    flask_mock.config['RSA_PRIVATE_KEY_PATH'] = TEST_PRIVATE_KEY_PATH_CONF
    flask_mock.config['RSA_PUBLIC_KEY_PATH'] = 'bla'

    with pytest.raises(FileNotFoundError):
        TestRSA(flask_mock)

    flask_mock.config['RSA_PUBLIC_KEY_PATH'] = None

    with pytest.raises(TypeError):
        TestRSA(flask_mock)

    flask_mock.config['RSA_PRIVATE_KEY_PATH'] = None
    flask_mock.config['RSA_PUBLIC_KEY_PATH'] = TEST_PUBLIC_KEY_PATH_CONF

    with pytest.raises(TypeError):
        TestRSA(flask_mock)


def test_config_rsa_keys(flask_mock):
    flask_mock.config['RSA_PRIVATE_KEY_PATH'] = TEST_PRIVATE_KEY_PATH_CONF
    flask_mock.config['RSA_PUBLIC_KEY_PATH'] = TEST_PUBLIC_KEY_PATH_CONF

    uut = TestRSA(flask_mock)

    assert not os.path.isfile(TEST_PRIVATE_KEY_PATH)
    assert not os.path.isfile(TEST_PUBLIC_KEY_PATH)
