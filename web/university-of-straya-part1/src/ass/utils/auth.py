import jwt, re, requests
from flask import current_app
from utils.cache import cache

TOKEN_URL_PATH = 'http://127.0.0.1:8080{path}'

@cache.memoize(60)
def validate_token(jwt_token: str):
    iss: str = jwt.get_unverified_header(jwt_token).get("iss", None)
    if iss is None:
        raise Exception("Where on earth do I grab the public key??????")

    if not bool(re.search(r'^/api/auth/pub-key', iss)):
        raise Exception("ISS needs to match ^/api/auth/pub-key!")

    r = requests.get(TOKEN_URL_PATH.format(path=iss))
    public_key = r.text
    return jwt.decode(jwt_token, public_key, algorithms=["RS256"])

def login_user(user_id: int) -> str:
    jwt_token: str = jwt.encode(
        {"id": user_id},
        current_app.config["API_PRIVATE_KEY"],
        headers={"iss": "/api/auth/pub-key"},
        algorithm='RS256'
    )
    return jwt_token