import os
import time
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tsl-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode({'id': self.id, 'exp': time.time() + expires_in}, app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])


class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), index=True)
    message = db.Column(db.String(512))


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    if username is None or password is None:
        abort(400)  # missing arguments

    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'status': 'User already exist'}), 400  # existing user

    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()

    user_info = {'username': user.username}
    user_location = {'Location': url_for('get_user', id=user.id, _external=True)}

    return jsonify(user_info), 201, user_location


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)

    if not user:
        abort(400)

    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/messages', methods=['POST'])
@auth.login_required
def save_message():
    message = request.json.get('message')

    if not message:
        abort(400)  # missing arguments

    msg = Message(name=g.user.username, message=message)
    db.session.add(msg)
    db.session.commit()

    return jsonify({'status': 'Successful'})


@app.route('/api/messages', methods=['GET'])
def get_message():
    messages = []

    for message in Message.query.all():
        messages.append({
            'id': message.id,
            'name': message.name,
            'message': message.message
        })

    return jsonify(messages)


@app.route('/')
def home():
    return jsonify({'status': 'Ok'})


def init_db():
    if not os.path.exists('db.sqlite'):
        db.create_all()


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
