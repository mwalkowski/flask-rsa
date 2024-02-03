# Server.py

This file contains a Flask server implementation for user registration, login, and signed request handling using RSA signatures.

## Dependencies
- Flask
- Flask-SQLAlchemy
- Flask-Bcrypt
- Flask-RSA
- cryptography

## Usage

1. Install the required packages from `requirements.txt`:
    ```bash
    pip install -r requirements.txt
    ```

2. Run the server using the following command:
    ```bash
    python server.py
    ```

3. The server will run on `http://127.0.0.1:5000`.

## Endpoints

### `/register` (POST)
- Register a new user with a unique username, password, and public key.

### `/login` (POST)
- Authenticate a user with a username and password, returning an authentication token.

### `/signed-body` (POST)
- Accept a signed request with a valid access token, verifying the RSA signature.

## RSA Signature Authentication

- RSA signatures are used for secure communication.
- Tokens are generated during login and used for subsequent signed requests.
- The server's public key is exposed at `/public-key`.

## Database

- SQLite is used as the database backend.
- The `Users` table stores user information.

## Running the Server

- The server will create a SQLite database file (`db.sqlite`) if it does not exist.
- Run the server in debug mode with automatic database commit.


# Client.py

This file contains a sample client implementation that interacts with the server.

## Dependencies
- requests
- cryptography

## Usage

1. Ensure the server is running.

2. Run the client using the following command:
    ```bash
    python client.py
    ```

3. The client will register a new user, login, and send a signed request to the server.

## Client Functions

- `generate_keys`: Generates RSA private and public keys.
- `get_server_public_key`: Retrieves the server's public key.
- `register_user`: Registers a new user on the server.
- `login`: Logs in a user and obtains an authentication token.
- `create_signature_input`: Creates input for generating an RSA signature.
- `generate_signature`: Generates an RSA signature for a given input.
- `send_signed_request`: Sends a signed request to the server.
- `add_signature`: Adds an RSA signature to request headers.
- `is_signature_correct`: Checks if the server's signature is correct.

## Running the Client

- The client generates a random username and password for registration and login.
- It interacts with the server to demonstrate user registration, login, and signed request handling.

# Requirements.txt

This file lists the required Python packages for running the server and client.

## Dependencies
- requests
- Flask (v3.0.0)
- Flask-SQLAlchemy (v3.1.1)
- cryptography (v42.0.2)
- flask_rsa
- Flask-Bcrypt (v1.0.1)
