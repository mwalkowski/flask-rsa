import base64
import json
import os
import re
import uuid
import pytest

from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from flask_rsa import RSA
from flask import Flask, jsonify


SIGNATURE_HEADER = 'X-Signature'
NONCE_HEADER = 'X-Nonce-Value'
NONCE_QUEUE_SIZE_LIMIT = 10
NONCE_CREATED_AT_HEADER = 'X-Nonce-Created-At'
TIME_DIFF_TOLERANCE_IN_SECONDS = 10.0
PUBLIC_KEY_URL = '/public-key'
UUID_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$"
PRIVATE_KEY = os.path.join(os.getcwd(), 'tests', 'data', 'private.key')
PUBLIC_KEY = os.path.join(os.getcwd(), 'tests', 'data', 'public.pem')


def read_private_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )


def create_signature(method, nonce, nonce_created_at, request_data):
    signature_input = "{}{}{}{}{}".format(method, '/signed-body', nonce, nonce_created_at, request_data)
    signature_input_b64 = base64.standard_b64encode(signature_input.encode())
    signature = read_private_key(PRIVATE_KEY).sign(
        signature_input_b64,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())
    return base64.standard_b64encode(signature).decode('utf-8')


@pytest.fixture()
def app():
    app = Flask(__name__)
    app.config['RSA_PRIVATE_KEY_PATH'] = PRIVATE_KEY
    app.config['RSA_PUBLIC_KEY_PATH'] = PUBLIC_KEY

    rsa = RSA(app)

    @app.route("/signed-body", methods=["GET", "POST", "PATCH", "PUT", "DELETE"])
    @rsa.signature_required()
    def signed_body():
        return jsonify({"msg": "Ok!"})

    app.config.update({
        "TESTING": True,
    })

    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()


def test_nonce_header_not_exists(client):
    response = client.post("/signed-body", json={})

    assert response.status_code == 403
    assert response.json == {'error': F'Missing header: {NONCE_HEADER}'}


def test_nonce_created_at_header_not_exists(client):
    response = client.post("/signed-body", headers={NONCE_HEADER: "a"}, json={})

    assert response.status_code == 403
    assert response.json == {'error': F'Missing header: {NONCE_CREATED_AT_HEADER}'}


def test_signature_header_not_exists(client):
    headers = {
        NONCE_HEADER: "a",
        NONCE_CREATED_AT_HEADER: "b",
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': F'Missing header: {SIGNATURE_HEADER}'}


def test_nonce_header_is_incorrect(client):
    headers = {
        NONCE_HEADER: "a",
        NONCE_CREATED_AT_HEADER: "b",
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "Nonce is already used or incorrect"}


def test_nonce_header_is_duplicated(client):
    headers = {
        NONCE_HEADER: uuid.uuid4(),
        NONCE_CREATED_AT_HEADER: "b",
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "The request is time-barred"}

    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "Nonce is already used or incorrect"}


def test_nonce_created_at_header_invalid(client):
    headers = {
        NONCE_HEADER: uuid.uuid4(),
        NONCE_CREATED_AT_HEADER: "b",
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "The request is time-barred"}


def test_nonce_created_at_header_time_barred(client):
    nonce_created_at = datetime.now(timezone.utc)
    nonce_created_at -= timedelta(days=0, seconds=TIME_DIFF_TOLERANCE_IN_SECONDS + 1)
    headers = {
        NONCE_HEADER: uuid.uuid4(),
        NONCE_CREATED_AT_HEADER: nonce_created_at.isoformat(),
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "The request is time-barred"}


def test_signature_invalid(client):
    headers = {
        NONCE_HEADER: uuid.uuid4(),
        NONCE_CREATED_AT_HEADER: datetime.now(timezone.utc).isoformat(),
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={'msg': 'msg'})

    assert response.status_code == 403
    assert response.json == {'error': "Invalid Signature"}


@pytest.mark.parametrize("method", ["GET", "DELETE", "POST", "PATCH", "PUT"])
def test_signature_ok(method, client):
    nonce = uuid.uuid4()
    nonce_created_at = datetime.now(timezone.utc).isoformat()
    request_data = ''

    if method != ["GET", "DELETE"]:
        request_data = json.dumps({'msg': 'msg'})

    headers = {
        NONCE_HEADER: nonce,
        NONCE_CREATED_AT_HEADER: nonce_created_at,
        SIGNATURE_HEADER: create_signature(method, nonce, nonce_created_at, request_data)
    }
    response = client.open(method=method, path="/signed-body", headers=headers, json=json.loads(request_data))

    assert response.status_code == 200
    assert response.json == {"msg": "Ok!"}

    assert NONCE_HEADER in response.headers
    assert nonce != response.headers[NONCE_HEADER]
    assert re.match(UUID_PATTERN, response.headers[NONCE_HEADER])

    assert NONCE_CREATED_AT_HEADER in response.headers
    assert nonce_created_at != response.headers[NONCE_CREATED_AT_HEADER]
    assert datetime.fromisoformat(response.headers[NONCE_CREATED_AT_HEADER])

    assert SIGNATURE_HEADER in response.headers
    assert create_signature(method, response.headers[NONCE_HEADER], response.headers[NONCE_CREATED_AT_HEADER], response.data)


def test_get_public_key_endpoint(client):
    response = client.get(PUBLIC_KEY_URL)

    assert response.status_code == 200
    with open(PUBLIC_KEY, 'r') as f:
        assert response.json == {'public_key': f.read()}
