"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import bcrypt


api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/users', methods=['GET'])
def get_users():
    usuarios = db.session.execute(db.select(User)).scalars().all()
    return jsonify({'total': len(usuarios), 'users': [user.serialize() for user in usuarios]}), 200


@api.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data['email']
    password = data['password']

    if not email or not password:
        return jsonify({'msg': 'Email y password son obligatorios'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'msg': 'Usuario ya registrado'}), 400

    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

    nuevo_usuario = User(
        email=email, password=password_hash.decode('utf-8'), is_active=True)

    db.session.add(nuevo_usuario)
    db.session.commit()

    return jsonify({'msg': "Usuario creado correctamente", 'user': nuevo_usuario.serialize()}), 200


@api.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data:
        return jsonify({'msg': 'No ha proporcionado información para login'}), 400

    email = data['email']
    password = data['password']

    usuario = User.query.filter_by(email=email).first()

    if usuario and bcrypt.checkpw(password.encode('utf-8'), usuario.password.encode('utf-8')):
        token = create_access_token(identity=str(usuario.id))
        return jsonify({'token': token, 'user': usuario.serialize()})

    return jsonify({'msg': 'Email o contraseña incorrectos'}), 401


@api.route('/privado', methods=['GET'])
@jwt_required()
def privado():
    id_usuario = get_jwt_identity()
    usuario = User.query.get(id_usuario)

    return jsonify({
        'msg': 'Acceso concedido a área privada',
        'user': usuario.serialize()
    })
