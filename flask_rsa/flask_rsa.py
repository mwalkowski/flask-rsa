import copy
import json
import os
import base64
import queue
import re
import uuid

from datetime import datetime, timezone
from functools import wraps
from requests import status_codes

from flask import jsonify, logging
from flask import request
from flask import make_response as flask_make_response

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes


_PRIVATE_KEY_PATH = 'private.key'
_PUBLIC_KEY_PATH = 'public.pem'
_SIGNATURE_HEADER = 'X-Signature'
_NONCE_HEADER = 'X-Nonce-Value'
_NONCE_QUEUE_SIZE_LIMIT = 10
_NONCE_CREATED_AT_HEADER = 'X-Nonce-Created-At'
_TIME_DIFF_TOLERANCE_IN_SECONDS = 10.0
_PAYLOAD_PLACEHOLDER = 'PAYLOAD_PLACEHOLDER'
_ENCRYPTED_PAYLOAD_KEY = 'encrypted_payload'
_PUBLIC_KEY_URL = '/public-key'

_UUID_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$"


class RSA:  # pylint: disable=too-many-instance-attributes

    def __init__(self, app=None):
        if app:
            self._logger = logging.create_logger(app)
            self._received_nonces = queue.Queue()
            self.init_app(app)

    def init_app(self, app):
        self._signature_header = app.config.get(
            'RSA_SIGNATURE_HEADER', _SIGNATURE_HEADER)
        self._nonce_header = app.config.get(
            'RSA_NONCE_HEADER', _NONCE_HEADER)
        self._nonce_created_at_header = app.config.get(
            'RSA_NONCE_CREATED_AT_HEADER', _NONCE_CREATED_AT_HEADER)
        self._nonce_queue_size_limit = app.config.get(
            'RSA_NONCE_QUEUE_SIZE_LIMIT', _NONCE_QUEUE_SIZE_LIMIT)
        self._time_diff_tolerance_in_seconds = app.config.get(
            'RSA_TIME_DIFF_TOLERANCE_IN_SECONDS', _TIME_DIFF_TOLERANCE_IN_SECONDS)
        self._payload_placeholder = app.config.get(
            'RSA_PAYLOAD_PLACEHOLDER', _PAYLOAD_PLACEHOLDER)
        self._encrypted_payload_key = app.config.get(
            'RSA_ENCRYPTED_PAYLOAD_KEY', _ENCRYPTED_PAYLOAD_KEY)
        self._encrypted_payload_structure = app.config.get(
            'RSA_ENCRYPTED_PAYLOAD_STRUCTURE',
            {self._encrypted_payload_key: self._payload_placeholder}
        )
        self._error_code = app.config.get(
            'RSA_ERROR_CODE', status_codes.codes.forbidden)  # pylint: disable=no-member

        self._requred_headers = [self._nonce_header,
                                 self._nonce_created_at_header,
                                 self._signature_header]

        private_key_path = app.config.get('RSA_PRIVATE_KEY_PATH', None)
        public_key_path = app.config.get('RSA_PUBLIC_KEY_PATH', None)
        self._prepare_server_rsa_keys(private_key_path, public_key_path)

        server_public_path = app.config.get('RSA_PUBLIC_KEY_URL', _PUBLIC_KEY_URL)
        app.add_url_rule(server_public_path, 'public-key',
                         self.get_server_public_key, methods=["GET"])

    def _prepare_server_rsa_keys(self, private_key_path, public_key_path):
        if not private_key_path and not public_key_path:
            self._load_or_generate_default_keys()
        else:
            try:
                self._server_public_key = self._read_public_key(public_key_path)
                self._server_private_key = self._read_private_key(private_key_path)
            except Exception as e:  # pylint: disable=broad-exception-caught
                self._logger.error(e)
                raise e

    def _load_or_generate_default_keys(self):
        self._logger.warning('RSA_PRIVATE_KEY_PATH and RSA_PUBLIC_KEY_PATH not set')
        public_key_path = os.path.join(os.getcwd(), _PUBLIC_KEY_PATH)
        private_key_path = os.path.join(os.getcwd(), _PRIVATE_KEY_PATH)
        try:
            self._server_public_key = self._read_public_key(public_key_path)
            self._server_private_key = self._read_private_key(private_key_path)
            self._logger.warning('Using last generated keys')
        except FileNotFoundError:
            self._logger.warning('Default keys not found, generating new one')

            self._server_private_key = self._generate_private_key()
            self._save_private_key(private_key_path)
            self._logger.warning('Private key saved in %s', private_key_path)

            self._server_public_key = self._server_private_key.public_key()
            self._save_public_key(public_key_path)
            self._logger.warning('Public key saved in %s', public_key_path)

    def _save_public_key(self, public_key_path):
        pem = self._server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self._save_key(pem, public_key_path)

    def _save_private_key(self, private_key_path):
        pem = self._server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        self._save_key(pem, private_key_path)

    @staticmethod
    def _save_key(pem, private_key_path):
        with open(private_key_path, "wb") as f:
            f.write(pem)

    @staticmethod
    def _generate_private_key():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return private_key

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

                if not self._is_signature_correct(request):
                    return self._make_response("Invalid Signature")

                return self._add_signature(f(*args, **kwargs), request)

            return decorator
        return _signature_required

    def encrypted_request(self):
        def _encrypted_request(f):
            @wraps(f)
            def decorator(*args, **kwargs):
                msg = request.get_json()
                if self._encrypted_payload_key in msg:

                    try:
                        plaintext = self._server_private_key.decrypt(
                            base64.standard_b64decode(msg[self._encrypted_payload_key]),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        request_body = json.loads(base64.standard_b64decode(plaintext))
                        return f(request_body, *args, **kwargs)
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        self._logger.error('Decryption problem %s', e)
                        return self._make_response('Decryption problem')
                else:
                    return self._make_response(f'Missing {self._encrypted_payload_key} param')

            return decorator

        return _encrypted_request

    def encrypted_response(self):
        def _encrypted_response(f):
            @wraps(f)
            def decorator(*args, **kwargs):
                response = f(*args, **kwargs)
                ciphertext = self._get_user_public_key(request).encrypt(
                    base64.standard_b64encode(response.data),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_msg = copy.deepcopy(self._encrypted_payload_structure)
                encrypted_msg[self._encrypted_payload_key] = base64.standard_b64encode(
                    ciphertext).decode()
                response.data = json.dumps(encrypted_msg)
                return response
            return decorator
        return _encrypted_response

    def get_server_public_key(self):
        return jsonify({"public_key": self._server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()})

    def _get_user_public_key(self, request):  # pylint: disable=unused-argument
        return self._server_public_key

    def _verify(self, request, signature_input_b64, received_signature):
        try:
            self._get_user_public_key(request).verify(
                base64.standard_b64decode(received_signature),
                signature_input_b64,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        return True

    def _is_signature_correct(self, request) -> bool:
        nonce_value = request.headers[self._nonce_header]
        nonce_created_at = request.headers[self._nonce_created_at_header]
        signature_input_b64 = self._create_signature_input(
            nonce_created_at, nonce_value, request.method, request.path, request.data)
        return self._verify(request, signature_input_b64, request.headers[self._signature_header])

    @staticmethod
    def _create_signature_input(nonce_created_at, nonce_value, method, path, data):
        signature_input = (F"{method}{path}{nonce_value}"
                           F"{nonce_created_at}{data.decode()}")
        signature_input_b64 = base64.standard_b64encode(signature_input.encode())
        return signature_input_b64

    def _add_signature(self, response, request):
        nonce = uuid.uuid4()
        nonce_created_at = datetime.now(timezone.utc).isoformat()
        signature_input_b64 = self._create_signature_input(
            nonce_created_at, nonce, request.method, request.path, response.data)
        response.headers[self._signature_header] = self._generate_signature(signature_input_b64)
        response.headers[self._nonce_header] = nonce
        response.headers[self._nonce_created_at_header] = nonce_created_at

        return response

    def _generate_signature(self, signature_input_b64):
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
            time_diff = (datetime.now().astimezone(timezone.utc) -
                         datetime.fromisoformat(nonce_created_at))
            return time_diff.total_seconds() < self._time_diff_tolerance_in_seconds
        except Exception:  # pylint: disable=broad-exception-caught
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
        return flask_make_response(jsonify({"error": msg}), self._error_code)

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
            return RSA._load_public_key(key_file.read())

    @staticmethod
    def _load_public_key(public_key):
        return serialization.load_pem_public_key(public_key)
