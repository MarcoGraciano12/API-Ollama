"""
Módulo de vistas relacionadas con la autenticación y gestión de usuarios.

Este módulo define las rutas y clases necesarias para el registro, inicio de sesión,
cerrar sesión y refresco de tokens JWT. Utiliza Flask-Smorest para definir los endpoints
como Blueprints, JWT-Extended para la autenticación, y Passlib para el hash de contraseñas.
"""

from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import create_access_token, get_jwt, jwt_required, create_refresh_token, get_jwt_identity
from passlib.hash import pbkdf2_sha256

from db import db
from models import UserModel
from schemas import UserSchema
from blocklist import BLOCKLIST

# Se define un Blueprint que agrupa las rutas relacionadas con usuarios.
blp = Blueprint("Users", "users", description="Operaciones sobre los usuarios del sistema.")


@blp.route("/register")
class UserRegister(MethodView):
    """
    Vista para registrar nuevos usuarios.

    POST:
        Espera datos válidos de usuario según el esquema `UserSchema`.
        Verifica si el nombre de usuario ya existe.
        Encripta la contraseña antes de guardar el usuario en la base de datos.
    """

    @blp.arguments(UserSchema)
    def post(self, user_data):
        """
        Registra un nuevo usuario en el sistema.

        Args:
            user_data (dict): Diccionario con las claves 'username' y 'password'.

        Returns:
            dict: Mensaje de éxito.
            int: Código de estado HTTP 201 si se creó correctamente, 409 si ya existe.
        """
        # Verifica si el nombre de usuario ya está en uso
        if UserModel.query.filter(UserModel.username == user_data["username"]).first():
            abort(409, message="El nombre de usuario ya se encuentra registrado.")

        # Se crea una instancia del usuario con la contraseña hasheada
        user = UserModel(
            username=user_data["username"],
            password=pbkdf2_sha256.hash(user_data["password"])
        )
        db.session.add(user)
        db.session.commit()

        return {"message": "El usuario se creó de manera correcta."}, 201


@blp.route("/login")
class UserLogin(MethodView):
    """
    Vista para autenticar a los usuarios mediante nombre de usuario y contraseña.

    POST:
        Verifica las credenciales y devuelve tokens JWT si son válidas.
    """

    @blp.arguments(UserSchema)
    def post(self, user_data):
        """
        Auténtica a un usuario existente.

        Args:
            user_data (dict): Diccionario con las claves 'username' y 'password'.

        Returns:
            dict: Access token y refresh token si las credenciales son correctas.
            int: Código de estado HTTP 200 si es exitoso, 401 si las credenciales fallan.
        """
        # Busca al usuario en la base de datos por nombre de usuario
        user = UserModel.query.filter(
            UserModel.username == user_data["username"]
        ).first()

        # Verifica si el usuario existe y si la contraseña coincide
        if user and pbkdf2_sha256.verify(user_data["password"], user.password):
            access_token = create_access_token(identity=str(user.id), fresh=True)
            refresh_token = create_refresh_token(str(user.id))
            return {"access_token": access_token, "refresh_token": refresh_token}, 200

        # Si las credenciales no son válidas, devuelve error
        abort(401, message="Credenciales Inválidas.")


@blp.route("/logout")
class UserLogout(MethodView):
    """
    Vista para cerrar la sesión del usuario.

    POST:
        Invalida el token de acceso actual añadiéndolo a una lista de bloqueo.
        Requiere autenticación JWT.
    """

    @jwt_required()
    def post(self):
        """
        Cierra la sesión del usuario autenticado.

        El token actual se añade a la BLOCKLIST para que no pueda ser reutilizado.

        Returns:
            dict: Mensaje de éxito.
            int: Código de estado HTTP 200.
        """
        # Se obtiene el identificador único del token actual (JTI)
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"message": "Se ha cerrado la sesión de manera correcta."}, 200


@blp.route("/refresh")
class TokenRefresh(MethodView):
    """
    Vista para generar un nuevo token de acceso usando un refresh token.

    POST:
        Requiere un refresh token válido.
        Invalida el refresh token usado añadiéndolo a la lista de bloqueo.
    """

    @jwt_required(refresh=True)
    def post(self):
        """
        Genera un nuevo token de acceso (no fresh).

        Returns:
            dict: Nuevo token de acceso.
            int: Código de estado HTTP 200.
        """

        # Obtiene la identidad del usuario del refresh token
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        # Se invalida el refresh token actual añadiéndolo a la BLOCKLIST
        jti = get_jwt()["jti"]
        BLOCKLIST.add(jti)
        return {"access_token": new_token}, 200


@blp.route("/user/<int:user_id>")
class User(MethodView):

    @jwt_required()
    @blp.response(200, UserSchema)
    def get(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        return user

    @jwt_required(fresh=True)
    def delete(self, user_id):
        current_user_id = get_jwt_identity()

        if str(user_id) == str(current_user_id):
            abort(403, message="No puedes eliminar tu propio usuario.")

        user = UserModel.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {"message": "Se ha eliminado el usuario."}, 200


@blp.route("/users")
class Users(MethodView):
    @jwt_required()
    @blp.response(200, UserSchema(many=True))
    def get(self):
        return UserModel.query.all()