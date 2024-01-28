from flask import Flask, jsonify
from flask_rsa import RSA

app = Flask(__name__)
rsa = RSA(app)


@app.route("/signed-body", methods=["POST"])
@rsa.signature_required()
def signed_body():
    return jsonify({"msg": "Ok!"})


if __name__ == "__main__":
    app.run()
