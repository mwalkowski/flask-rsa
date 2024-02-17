[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)![example workflow](https://github.com/mwalkowski/flask-rsa/actions/workflows/python-package.yml/badge.svg)![PyPI - Downloads](https://img.shields.io/pypi/dm/flask-rsa)


# Flask RSA
This Flask extension provides server-side implementation of RSA-based request signature validation, encryption, and decryption. It enhances the security of web applications by ensuring the integrity, authenticity, and confidentiality of incoming requests and outgoing responses.

## Installation
Install the Flask RSA extension using pip:

```bash
pip install flask-rsa
```

## Usage
To use this extension in your Flask application, follow these steps:

1. Import the RSA class from the flask_rsa module.

```python
from flask_rsa import RSA
```
2. Create a Flask application and initialize the RSA extension.

```python
from flask import Flask

app = Flask(__name__)
rsa = RSA(app)
```

3.Decorate the route(s) that require RSA signature validation using the `@rsa.signature_required()` decorator.
```python
@app.route('/secure-endpoint', methods=['POST'])
@rsa.signature_required()
def secure_endpoint():
    # Your protected route logic here
    return jsonify({"message": "Request successfully validated and processed"})
```

4.(Optional) Decorate the route(s) that require RSA request body decryption using the `@rsa.encrypted_request()` decorator:
```python
@app.route('/encrypted-endpoint', methods=['POST'])
@rsa.encrypted_request()
def encrypted_request_endpoint(request_body):
    # Your encrypted route logic here
    return jsonify({"message": "Request successfully decrypted and processed"})
```

5.(Optional) Decorate the route(s) that require RSA response body encryption using the `@rsa.encrypted_response()` decorator:
```python
@app.route('/encrypted-endpoint', methods=['POST'])
@rsa.encrypted_response()
def encrypted_endpoint():
    # Your encrypted route logic here
    return jsonify({"message": "Response successfully encrypted and sent"})
```

6.(Optional) Decorate the route(s) that require RSA request body decryption, response body encryption, and signature validation using the flowing example:
```python
@app.route('/encrypted-endpoint', methods=['POST'])
@rsa.signature_required()
@rsa.encrypted_request()
@rsa.encrypted_response()
def encrypted_endpoint():
    # Your encrypted route logic here
    return jsonify({"message": "Response successfully encrypted and sent"})
```

7.(Optional) Customize the extension by adjusting the configuration parameters.
```python
app.config['RSA_SIGNATURE_HEADER'] = 'X-Signature'
app.config['RSA_NONCE_HEADER'] = 'X-Nonce-Value'
# Add more configuration parameters as needed
```
5. Run your Flask application as usual.

## Configuration Parameters
* `RSA_SIGNATURE_HEADER`: Header name for the RSA signature (default: `X-Signature`).
* `RSA_NONCE_HEADER`: Header name for the nonce value (default: `X-Nonce-Value`).
* `RSA_NONCE_CREATED_AT_HEADER`: Header name for the nonce creation timestamp (default: `X-Nonce-Created-At`).
* `RSA_NONCE_QUEUE_SIZE_LIMIT`: Limit on the number of nonces stored in the queue (default: 10).
* `RSA_TIME_DIFF_TOLERANCE_IN_SECONDS`: Time difference tolerance for nonce validation (default: 10.0 seconds).
* `RSA_PUBLIC_KEY_URL`: Endpoint URL for exposing the server's public key (default: `/public-key`).
* `RSA_PRIVATE_KEY_PATH` and `RSA_PUBLIC_KEY_PATH`: Paths to the private and public keys, respectively. If not provided, new keys will be generated.
* `RSA_ERROR_CODE`: HTTP status code to return in case of validation failure (default: 403).
* `RSA_PAYLOAD_PLACEHOLDER`: Placeholder for encrypted payload in request/response (default: `PAYLOAD_PLACEHOLDER`).
* `RSA_ENCRYPTED_PAYLOAD_KEY`: Key name for encrypted payload in request/response (default: `encrypted_payload`).
* `RSA_ENCRYPTED_PAYLOAD_STRUCTURE`: Structure for encrypted payload in request/response (default: ```{'encrypted_payload': 'PAYLOAD_PLACEHOLDER'}```).

## Example

For a practical example of how to use this extension, refer to the provided [example code](./examples).

### User Key Verification Extension
For additional user key verification, extend the RSA class:
```python
from flask_rsa import RSA as FlaskRsa

class RSA(FlaskRsa):
    def _get_user_public_key(self, request):
        return FlaskRsa._load_public_key(request.current_user.public_key.encode())
```

More code can be found in the [example/server.py](./examples/server.py) file.

### Signature Generation
To generate an RSA signature, use the create_signature_input and generate_signature functions:
```python
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
```

### Signature Addition
To add an RSA signature to headers, use the add_signature function:
```python
def add_signature(headers, method, path, request_body, private_key):
    nonce = str(uuid.uuid4())
    nonce_created_at = datetime.now(timezone.utc).isoformat()
    signature_input_b64 = create_signature_input(nonce_created_at, nonce, path, method,
                                                 request_body)
    headers[SIGNATURE_HEADER] = generate_signature(private_key, signature_input_b64)
    headers[NONCE_HEADER] = nonce
    headers[NONCE_CREATED_AT_HEADER] = nonce_created_at
    return headers
```

### Signature Verification
To verify an RSA signature, use the verify function:
```python
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
```

### Encryption
To encrypt request body, use the encrypt function:
```python
def encrypt(body, server_public_key):
    return base64.standard_b64encode(server_public_key.encrypt(
        base64.standard_b64encode(body.encode('utf-8')),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )).decode()
```

### Decryption
To decrypt response body, use the decrypt function:
```python
def decrypt(data, private_key):
    return base64.standard_b64decode(private_key.decrypt(
        base64.standard_b64decode(data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))
```
More code can be found in the [example/client.py](./examples/client.py) file.

## License
This extension is released under the MIT License. See the [LICENSE](./LICENSE) file for more details.
