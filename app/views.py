import base64
import datetime
import json
    
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import requests
from flask import render_template, redirect, request , url_for
from app import app
port ="8002"
CONNECTED_NODE_ADDRESS = "http://127.0.0.1:"+port

posts = []


def fetch_posts():
    get_chain_address = "{}/chain".format(CONNECTED_NODE_ADDRESS)
    response = requests.get(get_chain_address)
    if response.status_code == 200:
        content = []
        chain = json.loads(response.content)
        for block in chain["chain"]:
            for tx in block["transactions"]:
                tx["index"] = block["index"]
                tx["hash"] = block["previous_hash"]
                content.append(tx)

        global posts
        posts = sorted(content, key=lambda k: k['timestamp'],
                       reverse=True)


@app.route('/')
def index():
    fetch_posts()
    return render_template('index.html',
                           title='DinoCheems:'
                                 'Me dio amsiedad hacer esto',
                           posts=posts,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string)


@app.route('/submit', methods=['POST'])
def submit_textarea():
    post_content = request.form["content"]

    private_key, public_key = generate_key_pair(port)

    signature = sign_message(private_key, post_content.encode())
    public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    public_pem = base64.b64encode(public_bytes).decode()
    if verify_signature(public_pem, post_content.encode(), signature):
        
        author=port
        post_object = {
            'author': author,
            'pass': signature,
            'content': post_content,
            'public': public_pem
        }
        new_tx_address = "{}/new_transaction".format(CONNECTED_NODE_ADDRESS)
        requests.post(new_tx_address,
                    json=post_object,
                    headers={'Content-type': 'application/json'})
        
        return redirect(url_for('dialog', author=author)) 
    else:
        return redirect('Transacccion no valida')



@app.route('/dialog/<author>')
def dialog(author):
    dialog_html = "<h1>Notificación para {}</h1>".format(author)
    dialog_html += "<ul>"
    dialog_html += "<li>Tu mensaje fue enviado a la cadena</li>"
    dialog_html += "</ul>"
    return dialog_html

def generate_key_pair(author):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

import binascii

def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_hex = binascii.hexlify(signature).decode()
    return signature_hex

def verify_signature(public_base64, message, signature_hex):
    try:
        public_bytes = base64.b64decode(public_base64)
        public_key = serialization.load_der_public_key(public_bytes)
        signature = binascii.unhexlify(signature_hex)
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return None

def timestamp_to_string(epoch_time):
    return datetime.datetime.fromtimestamp(epoch_time).strftime('%H:%M')
