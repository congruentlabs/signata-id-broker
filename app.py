from datetime import datetime, timedelta
from functools import wraps

from eth_hash import Keccak256
import os
import hmac
import hashlib
from flask import Flask, request, abort
from eth_utils import is_address
from supabase import create_client, Client
import supabase

url: str = os.environ.get("ID_SUPABASE_URL")
key: str = os.environ.get("ID_SUPABASE_KEY")
seed: str = os.environ.get("SEED")
blockpass_secret: str = os.environ.get("BLOCKPASS_SECRET")

supabase: Client = create_client(url, key)

app = Flask(__name__)


def get_api_key(key):
    """
    Searches for a given API Key from the db
    @param key: API Key to search the db for
    @return: Record if found, None if not found
    """
    api_key_records = supabase.table("api_keys").select("*").eq('api_key', key).execute()
    if len(api_key_records.data) == 0:
        return None
    else:
        return api_key_records.data[0]


def validate_api_key(key, type):
    """
    Validates a given API Key
    @param key: API Key from Request
    @return: boolean
    """
    if key is None:
        return False
    api_key = get_api_key(key)
    if api_key is None:
        return False
    elif api_key["api_key"] == key and api_key["type"] == type:
        return True
    return False


def require_write_key(f):
    """
    @param f: Flask function
    @return: decorator
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if validate_api_key(request.headers.get('x-api-key'), 'write'):
            return f(*args, **kwargs)
        else:
            abort(401)

    return decorated


def require_read_key(f):
    """
    @param f: Flask function
    @return: decorator
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if validate_api_key(request.headers.get('x-api-key'), 'read'):
            return f(*args, **kwargs)
        else:
            abort(401)

    return decorated


@app.route("/")
def get_version():
    """
    """
    return "0.0.1"


@app.route("/api/v1/identity", methods=['POST'])
def modify_identity():
    """
    """
    data = request.json

    if not is_address(data.identity):
        return 'Invalid Address', 400

    # check the signature of the keys
    # queue the request to be completed


@app.route("/api/v1/identity", methods=['GET'])
def get_identity():
    """
    """
    data = request.json

    if not is_address(data.identity):
        return 'Invalid Address', 400

    # check the signature of the keys
    # 


@app.route("/api/v1/status", methods=['GET'])
def get_status():
    """
    """
    #eth_balance
    #sata_staked

    return
    # get the status of the identity broker
    # total tokens staked, eth balance, etc.


@app.route("/api/v1/kycRequests/<id>", methods=["GET"])
def get_signature(id):
    """
    """
    data = request.json
    signatures = supabase.table("blockpass_events").select("*").eq("refId", id).eq("status", "approved").execute()

    if len(signatures.data) == 0:
        # no data
        return "No Data", 204
    else:
        last_nonce = supabase.table("kyc_last_nonce").select("last_nonce").limit(1).single()
        # increment the nonce
        new_nonce = last_nonce + 1;
        # generate the signature
        signature = ""
        # identity_address = data.refId
        # claim_digest = "0x8891c73a2637b13c5e7164598239f81256ea5e7b7dcdefd496a0acd25744091c"
        # hex_message = "0x1901"

        # update the nonce
        supabase.table("kyc_last_nonce").update({ last_nonce: new_nonce })

        return signature, 200


@app.route("/api/v1/blockpassWebhook", methods=['POST'])
def process_webhook():
    """
    Write the webhook events to the database.
    """
    data = request.json
    request_signature = request.headers['X-Hub-Signature']

    signature = hmac.new(bytes(blockpass_secret, 'utf-8'), msg=request.data, digestmod=hashlib.sha256).hexdigest()

    if request_signature == signature:
        supabase.table('blockpass_events').insert(data).execute()
        return 'Event Added', 200
    else:
        return 'Invalid Signature', 403
