import os
import jwt
import datetime
from functools import wraps

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_rsa import RSA as FlaskRsa


app = Flask(__name__)

app.config['SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class RSA(FlaskRsa):
    def _get_user_public_key(self, request):
        return FlaskRsa._load_public_key(request.current_user.public_key.encode())


rsa = RSA(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    public_key = db.Column(db.String(512))


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return make_response(jsonify({'message': 'a valid token is missing'}), 401)

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(id=data['id']).first()
        except:
            return make_response(jsonify({'message': 'token is invalid'}), 401)

        request.current_user = current_user
        return f(current_user, *args, **kwargs)

    return decorator


@app.route('/register', methods=['POST'])
def signup_user():
    data = request.get_json()

    hashed_password = bcrypt.generate_password_hash(data['password'])
    new_user = Users(name=data['username'], password=hashed_password, public_key=data['public_key'])
    db.session.add(new_user)
    db.session.commit()

    return make_response(jsonify({'message': 'registration successfully'}), 201)


@app.route('/login', methods=['POST'])
def login_user():
    auth = request.get_json()

    if not auth or not 'username' in auth or not 'password' in auth:
        return make_response('could not verify', 401, {'Authentication': 'login required"'})

    user = Users.query.filter_by(name=auth['username']).first()

    if bcrypt.check_password_hash(user.password, auth['password']):
        token = jwt.encode({'id': user.id,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)},
                           app.config['SECRET_KEY'], "HS256")
        return jsonify({'token': token})

    return make_response('could not verify', 401, {'Authentication': '"login required"'})


@app.route('/signed-body', methods=['POST'])
@token_required
@rsa.signature_required()
def signed_body(current_user):
    return jsonify({'signed': 'Ok'})


@app.route('/encrypted-singed-request', methods=['POST'])
@token_required
@rsa.signature_required()
@rsa.encrypted_request()
def encrypted_signed_body(request_body, current_user):
    return jsonify({'secret-accepted': F"response-{request_body['content']}"})


@app.route('/encrypted-request-response-and-signed', methods=['POST'])
@token_required
@rsa.signature_required()
@rsa.encrypted_request()
@rsa.encrypted_response()
def encrypted_all_signed(request_body, current_user):
    return jsonify({'secret': F"encrypted-response-{request_body['content']}"})


if __name__ == "__main__":
    if not os.path.exists('db.sqlite'):
        with app.app_context():
            db.create_all()
    app.run(debug=True)
