from myFlask import app

app.secret_key = os.urandom(24)
#세션관리
login_manager = LoginManager() 
login_manager.init_app(app)

class User:
   def __init__(self, user_id, email=None, passwordHash=None, authentication=False):
        self.user_id=user_id
        self.email = email
        self.passwordHash = passwordHash
        self.authentication = authentication

    def __repr__(self):
        r = {
            'user_id': self.user_id,
            'email': self.email,
            'passwd_hash': self.passwd_hash,
            'authentication': self.authentication,
        }
        return str(r)

    def can_login(self, passwd_hash):
        return self.passwd_hash == passwd_hash

    def is_active(self):
        return True

    def get_id(self):
        return self.user_id

    def is_authenticated(self):
        return self.authentication

    def is_anonymous(self):
        return False
