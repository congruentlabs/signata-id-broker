from datetime import datetime, timedelta
from functools import wraps
from web3 import Web3
import os
from flask import Flask, request, abort
from eth_utils import is_address
from supabase import create_client, Client
import supabase

url: str = os.environ.get("ID_SUPABASE_URL")
key: str = os.environ.get("ID_SUPABASE_KEY")
seed: str = os.environ.get("SEED")
web3_url: str = os.environ.get("WEB3_URL")

w3 = Web3(Web3.HTTPProvider(web3_url))

identity_address = ''
identity_abi = ''
identity_instance = w3.eth.contract(address=identity_address, abi=identity_abi)

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


def execute_queued():
    """
    """
