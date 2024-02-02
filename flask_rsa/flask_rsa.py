import os
import base64
import queue
import re
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from requests import status_codes
from datetime import datetime, timezone
from functools import wraps

from flask import jsonify, logging
from flask import request
from flask import make_response as flask_make_response


from cryptography.hazmat.primitives import serialization, hashes

_PRIVATE_KEY_PATH = 'private.key'
_PUBLIC_KEY_PATH = 'public.pem'
_SIGNATURE_HEADER = 'X-Signature'
_NONCE_HEADER = 'X-Nonce-Value'
_NONCE_QUEUE_SIZE_LIMIT = 10
_NONCE_CREATED_AT_HEADER = 'X-Nonce-Created-At'
_TIME_DIFF_TOLERANCE_IN_SECONDS = 10.0
_PUBLIC_KEY_URL = '/public-key'

_UUID_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$"


class RSA(object):

    def __init__(self, app=None):
        self._received_nonces = queue.Queue()
        if app:
            self._logger = logging.create_logger(app)
            self.init_app(app)

    def init_app(self, app):
        self._signature_header = app.config.get('RSA_SIGNATURE_HEADER', _SIGNATURE_HEADER)
        self._nonce_header = app.config.get('RSA_NONCE_HEADER', _NONCE_HEADER)
        self._nonce_created_at_header = app.config.get('RSA_NONCE_CREATED_AT_HEADER', _NONCE_CREATED_AT_HEADER)
        self._nonce_queue_size_limit = app.config.get('RSA_NONCE_QUEUE_SIZE_LIMIT', _NONCE_QUEUE_SIZE_LIMIT)
        self._time_diff_tolerance_in_seconds = app.config.get('RSA_NONCE_CREATED_AT_HEADER', _TIME_DIFF_TOLERANCE_IN_SECONDS)
        self._error_code = app.config.get('RSA_ERROR_CODE', status_codes.codes.forbidden)
        self._requred_headers = [self._nonce_header, self._nonce_created_at_header, self._signature_header]

        server_public_path = app.config.get('RSA_PUBLIC_KEY_URL', _PUBLIC_KEY_URL)
        app.add_url_rule(server_public_path, 'public-key', self.get_server_public_key, methods=["GET"])

        private_key_path = app.config.get('RSA_PRIVATE_KEY_PATH', None)
        public_key_path = app.config.get('RSA_PUBLIC_KEY_PATH', None)

        self._prepare_server_rsa_keys(private_key_path, public_key_path)

    def _prepare_server_rsa_keys(self, private_key_path, public_key_path):
        if not private_key_path and not public_key_path:
            self._logger.warning('RSA_PRIVATE_KEY_PATH and RSA_PUBLIC_KEY_PATH not set')
            public_key_path = os.path.join(os.getcwd(), _PUBLIC_KEY_PATH)
            private_key_path = os.path.join(os.getcwd(), _PRIVATE_KEY_PATH)

            try:
                self._server_public_key = self._read_public_key(public_key_path)
                self._server_private_key = self._read_private_key(private_key_path)
                self._logger.warning('Using last generated keys')
            except FileNotFoundError:
                self._logger.warning('Default keys not found, generating new one')

                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                self._server_private_key = private_key
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                with open(private_key_path, "wb") as f:
                    f.write(pem)
                self._logger.warning(F'Private key saved in {private_key_path}')

                self._server_public_key = private_key.public_key()
                pem = self._server_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                with open(public_key_path, "wb") as f:
                    f.write(pem)
                self._logger.warning(F'Public key saved in {public_key_path}')

        else:
            try:
                self._server_public_key = self._read_public_key(public_key_path)
                self._server_private_key = self._read_private_key(private_key_path)
            except FileNotFoundError as e:
                self._logger.error(e)
                raise e

    def signature_required(self):

        def _signature_required(f):
            @wraps(f)
            def decorator(*args, **kwargs):
                missing_header = self._check_headers_exists(request)

                if missing_header:
                    return self._make_response(f"Missing header: {missing_header}")

                if not self._is_nonce_correct(request):
                    return self._make_response("Nonce is already used or incorrect")

                if not self._is_nonce_created_at_correct(request):
                    return self._make_response("The request is time-barred")

                if not self.is_signature_correct(request):
                    return self._make_response("Invalid Signature")

                return self.add_signature(f(*args, **kwargs), request)

            return decorator
        return _signature_required

    def get_server_public_key(self):
        return jsonify({"public_key": self._server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()})

    def get_user_public_key(self, request):
        return self._server_public_key

    def verify(self, request, signature_input_b64, received_signature):
        try:
            self.get_user_public_key(request).verify(
                base64.standard_b64decode(received_signature),
                signature_input_b64,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature as e:
            return False
        return True

    def is_signature_correct(self, request):
        nonce_value = request.headers[self._nonce_header]
        nonce_created_at = request.headers[self._nonce_created_at_header]
        signature_input_b64 = self._create_signature_input(nonce_created_at, nonce_value, request)
        return self.verify(request, signature_input_b64, request.headers[self._signature_header])

    @staticmethod
    def _create_signature_input(nonce_created_at, nonce_value, request):
        signature_input = "{}{}{}{}{}".format(request.method, request.path,
                                              nonce_value, nonce_created_at, request.data.decode())
        signature_input_b64 = base64.standard_b64encode(signature_input.encode())
        return signature_input_b64

    def add_signature(self, response, request):
        nonce = uuid.uuid4()
        nonce_created_at = datetime.now(timezone.utc).isoformat()
        signature_input_b64 = self._create_signature_input(nonce_created_at, nonce, request)
        response.headers[self._signature_header] = self.generate_signature(signature_input_b64)
        response.headers[self._nonce_header] = nonce
        response.headers[self._nonce_created_at_header] = nonce_created_at

        return response

    def generate_signature(self, signature_input_b64):
        return base64.standard_b64encode(self._server_private_key.sign(
            signature_input_b64,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())
        ).decode('utf-8')

    def _check_headers_exists(self, request):
        for header in self._requred_headers:
            if header not in request.headers:
                return header
        return None

    def _is_nonce_created_at_correct(self, request):
        try:
            nonce_created_at = request.headers[self._nonce_created_at_header]
            time_diff = datetime.now().astimezone(timezone.utc) - datetime.fromisoformat(nonce_created_at)
            return time_diff.total_seconds() < self._time_diff_tolerance_in_seconds
        except Exception:
            return False

    def _is_nonce_correct(self, request):
        nonce = request.headers[self._nonce_header]
        if re.match(_UUID_PATTERN, nonce) and nonce not in self._received_nonces.queue:
            self._clean_up_the_received_nonces_queue()
            self._received_nonces.put(nonce, block=True)
            return True
        return False

    def _clean_up_the_received_nonces_queue(self):
        if self._received_nonces.qsize() >= self._nonce_queue_size_limit:
            self._received_nonces.get(block=True)

    def _make_response(self, msg):
        return flask_make_response(jsonify({"error": msg}), self._error_code )

    @staticmethod
    def _read_private_key(filename):
        with open(filename, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )

    @staticmethod
    def _read_public_key(filename):
        with open(filename, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())
