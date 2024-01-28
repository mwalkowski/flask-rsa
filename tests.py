import base64
import datetime
import json
import uuid

import pytest

from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15 as pkcs_signature

from flask_rsa import RSA
from flask import Flask, jsonify


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
    assert response.json == {'error': F'Missing header: {RSA._NONCE_HEADER}'}


def test_NONCE_CREATED_AT_HEADER_not_exists(client):
    response = client.post("/signed-body", headers={RSA._NONCE_HEADER: "a"}, json={})

    assert response.status_code == 403
    assert response.json == {'error': F'Missing header: {RSA._NONCE_CREATED_AT_HEADER}'}


def test_SIGNATURE_HEADER_not_exists(client):
    headers = {
        RSA._NONCE_HEADER: "a",
        RSA._NONCE_CREATED_AT_HEADER: "b",
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': F'Missing header: {RSA._SIGNATURE_HEADER}'}


def test_NONCE_HEADER_is_incorrect(client):
    headers = {
        RSA._NONCE_HEADER: "a",
        RSA._NONCE_CREATED_AT_HEADER: "b",
        RSA._SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "Nonce is already used or incorrect"}


def test_NONCE_HEADER_pool(client):
    for _ in range(30):
        headers = {
            RSA._NONCE_HEADER: uuid.uuid4(),
            RSA._NONCE_CREATED_AT_HEADER: "b",
            RSA._SIGNATURE_HEADER: "aaaa"
        }
        response = client.post("/signed-body", headers=headers, json={})

        assert response.status_code == 403
    assert RSA._received_nonces.qsize() == 10


def test_NONCE_HEADER_is_duplicated(client):
    headers = {
        RSA._NONCE_HEADER: uuid.uuid4(),
        RSA._NONCE_CREATED_AT_HEADER: "b",
        RSA._SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "The request is time-barred"}

    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "Nonce is already used or incorrect"}


def test_NONCE_CREATED_AT_HEADER_invalid(client):
    headers = {
        RSA._NONCE_HEADER: uuid.uuid4(),
        RSA._NONCE_CREATED_AT_HEADER: "b",
        RSA._SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "The request is time-barred"}

def test_NONCE_CREATED_AT_HEADER_time_barred(client):
    nonce_created_at = datetime.datetime.now(datetime.timezone.utc)
    nonce_created_at -= datetime.timedelta(days=0, seconds=RSA._TIME_DIFF_TOLERANCE_IN_SECONDS + 1)
    headers = {
        RSA._NONCE_HEADER: uuid.uuid4(),
        RSA._NONCE_CREATED_AT_HEADER: nonce_created_at.isoformat(),
        RSA._SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={})

    assert response.status_code == 403
    assert response.json == {'error': "The request is time-barred"}

def test_SIGNATURE_invalid(client):
    headers = {
        RSA._NONCE_HEADER: uuid.uuid4(),
        RSA._NONCE_CREATED_AT_HEADER: datetime.datetime.now(datetime.timezone.utc).isoformat(),
        RSA._SIGNATURE_HEADER: "aaaa"
    }
    response = client.post("/signed-body", headers=headers, json={'msg': 'msg'})

    assert response.status_code == 403
    assert response.json == {'error': "Invalid Signature"}

