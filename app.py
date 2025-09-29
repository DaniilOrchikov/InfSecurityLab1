import os
from datetime import timedelta
from markupsafe import escape

from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from dotenv import load_dotenv

load_dotenv()

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
JWT_SECRET = os.getenv("JWT_SECRET")

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = JWT_SECRET
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=2)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # хеш

    def check_password(self, plain_password: str) -> bool:
        return bcrypt.check_password_hash(self.password, plain_password)


class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        token = create_access_token(identity=str(user.id))
        return jsonify(access_token=token), 200

    return jsonify({"msg": "Invalid credentials"}), 401


@app.route("/api/data", methods=["GET"])
@jwt_required()
def get_posts():
    posts = Post.query.all()
    result = [
        {
            "id": p.id,
            "title": escape(p.title),
            "body": escape(p.body),
            "author_id": p.author,
        }
        for p in posts
    ]
    return jsonify(result), 200


@app.route("/api/post", methods=["POST"])
@jwt_required()
def create_post():
    user_id = int(get_jwt_identity())
    data = request.get_json(force=True)
    title = data.get("title")
    body = data.get("body")

    if not title or not body:
        return jsonify({"msg": "Title and body required"}), 400

    post = Post(title=title, body=body, author=user_id)
    db.session.add(post)
    db.session.commit()
    return jsonify({"msg": "Post created", "id": post.id}), 201


@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json(force=True)

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    if len(username) < 3 or len(password) < 6:
        return jsonify({"msg": "Username min 3, password min 6 chars"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username already taken"}), 409

    pw_hash = bcrypt.generate_password_hash(password).decode()
    user = User(username=username, password=pw_hash)

    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=str(user.id))

    return (
        jsonify(
            {
                "msg": "User registered",
                "user_id": user.id,
                "access_token": access_token,
            }
        ),
        201,
    )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)
