# Flask RSA Signature Validation
This Flask extension provides server-side implementation of RSA-based request signature validation. It enhances the security of web applications by ensuring the integrity and authenticity of incoming requests. The extension allows developers to easily integrate RSA signature validation into their Flask applications.

## Installation
Install the Flask RSA Signature Validation extension using pip:

```bash
pip install flask-rsa
```

## Usage
To use this extension in your Flask application, follow these steps:

1. Import the RSA class from the flask_rsa_signature module.

```python
from flask_rsa import RSA
```
2. Create a Flask application and initialize the RSA extension.

```python
from flask import Flask

app = Flask(__name__)
rsa = RSA(app)
```

3.Decorate the route(s) that require RSA signature validation using the @rsa.signature_required() decorator.
```python
@app.route('/secure-endpoint', methods=['POST'])
@rsa.signature_required()
def secure_endpoint():
    # Your protected route logic here
    return jsonify({"message": "Request successfully validated and processed"})
```

4.(Optional) Customize the extension by adjusting the configuration parameters.
```python
app.config['RSA_SIGNATURE_HEADER'] = 'X-Signature'
app.config['RSA_NONCE_HEADER'] = 'X-Nonce-Value'
# Add more configuration parameters as needed
```
5. Run your Flask application as usual.

## Configuration Parameters
* `RSA_SIGNATURE_HEADER`: Header name for the RSA signature (default: 'X-Signature').
* `RSA_NONCE_HEADER`: Header name for the nonce value (default: 'X-Nonce-Value').
* `RSA_NONCE_CREATED_AT_HEADER`: Header name for the nonce creation timestamp (default: 'X-Nonce-Created-At').
* `RSA_NONCE_QUEUE_SIZE_LIMIT`: Limit on the number of nonces stored in the queue (default: 10).
* `RSA_TIME_DIFF_TOLERANCE_IN_SECONDS`: Time difference tolerance for nonce validation (default: 10.0 seconds).
* `RSA_PUBLIC_KEY_URL`: Endpoint URL for exposing the server's public key (default: '/public-key').
* `RSA_PRIVATE_KEY_PATH` and `RSA_PUBLIC_KEY_PATH`: Paths to the private and public keys, respectively. If not provided, new keys will be generated.
* `RSA_ERROR_CODE`: HTTP status code to return in case of validation failure (default: 403).

## Example
For a practical example of how to use this extension, refer to the provided [example code](./examples/requests_signing.py).

## License
This extension is released under the MIT License. See the [LICENSE](./LICENSE) file for more details.