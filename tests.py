import datetime
import uuid

import pytest

from flask_rsa import RSA
from flask import Flask, jsonify


SIGNATURE_HEADER = 'X-Signature'
NONCE_HEADER = 'X-Nonce-Value'
NONCE_QUEUE_SIZE_LIMIT = 10
NONCE_CREATED_AT_HEADER = 'X-Nonce-Created-At'
TIME_DIFF_TOLERANCE_IN_SECONDS = 10.0
PUBLIC_KEY_URL = '/public-key'


@pytest.fixture()
def app():
    app = Flask(__name__)
    rsa = RSA(app)

    @app.route("/signed-body", methods=["POST"])
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


def test_NONCE_HEADER_not_exists(client):
    response = client.post("/signed-body", json={})

    assert response.status_code == 403
    assert response.json == {'error': F'Missing header: {NONCE_HEADER}'}


def test_NONCE_CREATED_AT_HEADER_not_exists(client):
    response = client.post("/signed-body", headers={NONCE_HEADER: "a"}, json={})

    assert response.status_code == 403
    assert response.json == {'error': F'Missing header: {NONCE_CREATED_AT_HEADER}'}


def test_SIGNATURE_HEADER_not_exists(client):
    headers = {
        NONCE_HEADER: "a",
        NONCE_CREATED_AT_HEADER: "b",
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': F'Missing header: {SIGNATURE_HEADER}'}


def test_NONCE_HEADER_is_incorrect(client):
    headers = {
        NONCE_HEADER: "a",
        NONCE_CREATED_AT_HEADER: "b",
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "Nonce is already used or incorrect"}


def test_NONCE_HEADER_is_duplicated(client):
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


def test_NONCE_CREATED_AT_HEADER_invalid(client):
    headers = {
        NONCE_HEADER: uuid.uuid4(),
        NONCE_CREATED_AT_HEADER: "b",
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "The request is time-barred"}

def test_NONCE_CREATED_AT_HEADER_time_barred(client):
    nonce_created_at = datetime.datetime.now(datetime.timezone.utc)
    nonce_created_at -= datetime.timedelta(days=0, seconds=TIME_DIFF_TOLERANCE_IN_SECONDS + 1)
    headers = {
        NONCE_HEADER: uuid.uuid4(),
        NONCE_CREATED_AT_HEADER: nonce_created_at.isoformat(),
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "The request is time-barred"}

def test_SIGNATURE_invalid(client):
    headers = {
        NONCE_HEADER: uuid.uuid4(),
        NONCE_CREATED_AT_HEADER: datetime.datetime.now(datetime.timezone.utc).isoformat(),
        SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={'msg': 'msg'})

    assert response.status_code == 403
    assert response.json == {'error': "Invalid Signature"}

