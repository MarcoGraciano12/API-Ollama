from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import create_access_token, get_jwt, jwt_required, create_refresh_token, get_jwt_identity
from passlib.hash import pbkdf2_sha256

from RAGController import ChromaDBManager as chromadb

# Se define un Blueprint que agrupa las rutas relacionadas con usuarios.
blp = Blueprint("RAG", __name__, description="Operaciones sobre la base de datos vectorial.")

rag = chromadb()

@blp.route("/collections")
class Collections(MethodView):

    def get(self):
        return rag.get_collections()