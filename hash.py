import hashlib #sha256으로 hash화
import bcrypt
from api import common
from api.errors import ApiUnauthorized


id = 'myId'.encode()
pw = 'myPassword'.encode()
hash_id = hashlib.sha256(id).hexdigest()

id2 = 'myId'.encode()
hash_id2 = hashlib.sha256(id2).hexdigest()

print(id)
print(hash_id)


#rainbow attack을 막기위해 보완법 salting 이용
#기존 비밀번호에 추가적으로 랜덤데이터를 더해 해시값을 계산
bcryptPw = bcrypt.hashpw(pw, bcrypt.gensalt())
bcryptPw_hex = bcrypt.hashpw(pw, bcrypt.gensalt()).hex()

print(bcryptPw)
print(bcryptPw_hex)


def authorize(request):
    """Requests an authorization token for a registered Account"""
    required_fields = ['email', 'password']
    common.validate_fields(required_fields, request.json)
    password = bytes(request.json.get('password'), 'utf-8')
    auth_info = await auth_query.fetch_info_by_email(
        request.app.config.DB_CONN, request.json.get('email'))
    if auth_info is None:
        raise ApiUnauthorized("No user with that email exists")
    hashed_password = auth_info.get('hashed_password')
    if not bcrypt.checkpw(password, hashed_password):
        raise ApiUnauthorized("Incorrect email or password")
    token = common.generate_auth_token(
        request.app.config.SECRET_KEY,
        auth_info.get('email'),
        auth_info.get('public_key'))
    return json(
        {
            'authorization': token
        })
