import base64
import json
import uuid
from datetime import datetime, timezone

import requests
from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

SERVER_ADDRESS = 'http://127.0.0.1:5000'
SIGNATURE_HEADER = 'X-Signature'
NONCE_HEADER = 'X-Nonce-Value'
NONCE_CREATED_AT_HEADER = 'X-Nonce-Created-At'


def generate_keys():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def get_server_public_key():
    response = requests.get(F'{SERVER_ADDRESS}/public-key')
    return serialization.load_pem_public_key(response.json()['public_key'].encode())


def register_user(username: str, password: str, public_key):
    key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    resp = requests.post(f'{SERVER_ADDRESS}/register',
                         json={'username': username, 'password': password, 'public_key': key})
    if resp.status_code != 201:
        print('Unable to register user')
        exit(1)


def login(username: str, password: str):
    resp = requests.post(f'{SERVER_ADDRESS}/login',
                         json={'username': username,
                               'password': password})
    return resp.json()['token']


def create_signature_input(nonce_created_at, nonce_value, path, method, request_body):
    signature_input = (F"{method}{path}{nonce_value}"
                       F"{nonce_created_at}{request_body}")
    signature_input_b64 = base64.standard_b64encode(signature_input.encode())
    return signature_input_b64


def generate_signature(private_key, signature_input_b64):
    return base64.standard_b64encode(private_key.sign(
        signature_input_b64,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())
    ).decode('utf-8')


def send_signed_request(path, private_key, token, request_body):
    headers = {'x-access-token': token}

    headers = add_signature(headers, 'POST', path,
                            request_body, private_key)

    headers['Content-Type'] = 'application/json'
    return requests.post(
        F'{SERVER_ADDRESS}/{path}',
        headers=headers,
        data=request_body
    )


def add_signature(headers, method, path, request_body, private_key):
    nonce = str(uuid.uuid4())
    nonce_created_at = datetime.now(timezone.utc).isoformat()
    signature_input_b64 = create_signature_input(nonce_created_at, nonce, path, method,
                                                 request_body)
    headers[SIGNATURE_HEADER] = generate_signature(private_key, signature_input_b64)
    headers[NONCE_HEADER] = nonce
    headers[NONCE_CREATED_AT_HEADER] = nonce_created_at
    return headers


def verify(server_public_key, signature_input_b64, received_signature):
    try:
        server_public_key.verify(
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


def is_signature_correct(response, path, method, server_public_key):
    nonce_value = response.headers[NONCE_HEADER]
    nonce_created_at = response.headers[NONCE_CREATED_AT_HEADER]
    signature_input_b64 = create_signature_input(
        nonce_created_at, nonce_value, method, path, response.text)

    try:
        server_public_key.verify(
            base64.standard_b64decode(response.headers[SIGNATURE_HEADER]),
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


def encrypt(body, server_public_key):
    return base64.standard_b64encode(server_public_key.encrypt(
        base64.standard_b64encode(body.encode('utf-8')),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )).decode()


def decrypt(data, private_key):
    return base64.standard_b64decode(private_key.decrypt(
        base64.standard_b64decode(data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))


if __name__ == "__main__":
    username = str(uuid.uuid4())
    print(F'Created user name: {username}')
    password = str(uuid.uuid4())
    print(F'Created password: {password}')

    private_key = generate_keys()
    print('Generated user private key')

    server_public_key = get_server_public_key()
    print('Downloaded server public key')

    register_user(username, password, private_key.public_key())
    print('User registered')

    token = login(username, password)
    print('User logged in')

    print(F'Received token: {token}')
    print('Sending signed request')
    response = send_signed_request('/signed-body', private_key, token, json.dumps({'TEST': 'Test'}))

    print(F'Response status code: {response.status_code}')
    print(F'Response body: {response.json()}')
    is_correct = is_signature_correct(response, "POST", "/signed-body", server_public_key)
    print(F'Is server signature correct?: {is_correct}')

    print('Sending encrypted and singed request')
    encrypted_body = encrypt(json.dumps({"content": "hello-world"}), server_public_key)
    response = send_signed_request('/encrypted-singed-request', private_key, token, json.dumps({"encrypted_payload": encrypted_body}))
    print(F'Response status code: {response.status_code}')
    print(F'Received response: {response.json()}')
    is_correct = is_signature_correct(response, "POST", '/encrypted-singed-request', server_public_key)
    print(F'Is server signature correct?: {is_correct}')

    print('Sending encrypted and singed request')
    encrypted_body = encrypt(json.dumps({"content": "hello-world"}), server_public_key)
    response = send_signed_request('/encrypted-request-response-and-signed', private_key, token, json.dumps({"encrypted_payload": encrypted_body}))
    print(F'Response status code: {response.status_code}')
    print(F'Received encrypted response: {response.json()}')
    is_correct = is_signature_correct(response, "POST", '/encrypted-request-response-and-signed', server_public_key)
    print(F'Is server signature correct?: {is_correct}')
    encrypted_payload = response.json()["encrypted_payload"]
    print(F'Decrypted response: {json.loads(decrypt(encrypted_payload, private_key))}')
