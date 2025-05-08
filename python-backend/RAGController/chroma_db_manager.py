"""
Módulo encargado de la gestión de una base de datos Chroma con incrustaciones vectoriales,
en el contexto de un sistema RAG (Retrieval-Augmented Generation).

Provee una clase ChromaDBManager que permite:

- Crear colecciones (entrenamientos) a partir de documentos.
- Eliminar, actualizar y consultar entrenamientos.
- Listar las categorías (colecciones) disponibles en la base de datos.

Este módulo extiende la funcionalidad de `EmbeddingsModel`, que proporciona los métodos
para procesar documentos y generar incrustaciones a partir de texto.
"""

# Importación de Módulos
import os
from langchain_chroma import Chroma
from langchain.chains import ConversationalRetrievalChain
from RAGController.embeddings_model import EmbeddingsModel


# Declaración de Clases
class ChromaDBManager(EmbeddingsModel):
    """
    Clase encargada de gestionar una base de datos de tipo Chroma, que almacena documentos
    vectorizados (incrustaciones) organizados por categorías (colecciones).

    Hereda de:
        EmbeddingsModel: Clase base que contiene los métodos de procesamiento y vectorización de texto.
    """

    def __init__(self, db_name="db", db_dir=r".\knowledge-base"):
        super().__init__()
        # Nombre de la base de datos
        self.__db_name = db_name
        # Ubicación de la base de datos
        self.__db_dir = db_dir
        # Se asegura la existencia de la carpeta que contiene a la base de datos
        os.makedirs(self.__db_dir, exist_ok=True)
        # Se obtiene la ruta a la base de datos
        self.__db_path = os.path.join(self.__db_dir, self.__db_name)
        # Se inicializa la conexión a la base de datos
        self.__db = Chroma(persist_directory=self.__db_path, embedding_function=self._embeddings)
        # Lista con el nombre de las colecciones disponibles.
        self.__collections = self.load_categories()['content']

    def create_collection(self, file_content: bytes, file_extension: str, category: str):
        """
        Método encargado de crear una nueva colección (entrenamiento) a partir de un documento ingresado por el usuario.

        Args:
            file_content (bytes): Contenido del documento.
            file_extension (str): Extensión del documento ingresado.
            category (str): Los metadatos (entrenamiento) que se le asignarán a los datos.

        Returns:
             dict: Un diccionario con el estado, mensaje y resultado de la operación.
                - 'status' (bool): Estado de la operación.
                - 'message' (str): Mensaje de éxito o error.
        """
        try:

            if category in self.__collections:
                return {'status': False, 'message': f'El nombre del entrenamiento {category} ya está registrado.'}

            # Se procesa el documento.
            text = self.process_document(file_content, file_extension)

            print(text)  # Depuración -> Eliminar

            if not text['status']:  # Si no se obtuvo el texto del documento.
                return text

            # Se obtienen las incrustaciones del texto procesado con los metadatos asignados.
            documents = self.create_embedding(text=text['content'], category=category)

            if not documents['status']:  # Si no se obtuvieron las incrustaciones con metadatos.
                return documents

            # Se agrega el texto dividido como incrustaciones a la base de datos.
            self.__db.add_documents(documents['content'])

            # Se agrega el nombre a las colecciones existentes.
            self.__collections.append(category)

            return {'status': True, 'message': f'Se ha creado el entrenamiento {category}.'}

        except Exception as error:
            return {'status': False, 'message': f'Se presentó un error al crear el entrenamiento: {str(error)}.'}

    def delete_collection(self, category: str):
        """
        Método encargado de eliminar la colección (entrenamiento) seleccionado por el usuario.

        Args:
            category (str): Nombre del entrenamiento (colección) a eliminar.

        Returns:
            dict: Un diccionario con el estado, mensaje y resultado de la operación.
                - 'status' (bool): Estado de la operación.
                - 'message' (str): Mensaje de éxito o error.
        """
        try:
            if not category in self.__collections:  # Si la colección no existe.
                return {'status': False, 'message': 'El entrenamiento no está registrado.'}

            # Se eliminan los documentos con los metadatos correspondientes.
            self.__db.delete(where={"category": category})

            # Se elimina el nombre del colección de la lista de colecciones.
            self.__collections.remove(category)

            return {'status': True, 'message': f"Se eliminó el entrenamiento {category}."}

        except Exception as error:
            return {'status': False, 'message': f'Ocurrió un error al eliminar el entrenamiento: {str(error)}'}

    def update_collection(self, file_content: bytes, file_extension: str, category: str):
        """
        Método encargado de actualizar una colección (entrenamiento) que el usuario a seleccionado.

        Args:
            file_content (bytes): Contenido del documento seleccionado por el usuario.
            file_extension (str): Extensión del documento seleccionado por el usuario.
            category (str): Nombre de la colección (entrenamiento) a la que se agregará la información del documento.

        Returns:
            dict: Un diccionario con el estado, mensaje y resultado de la operación.
                - 'status' (bool): Estado de la operación.
                - 'message' (str): Mensaje de éxito o error.
        """
        try:
            if not category in self.__collections:  # Si la colección no existe.
                return {'status': False, 'message': 'El entrenamiento seleccionado no se encuentra registrado.'}

            # Se procesa el documento.
            text = self.process_document(file_content, file_extension)

            if not text['status']:  # Si no se obtuvo el texto del documento.
                return text

            # Se obtienen pedazos del texto procesado con los metadatos asignados.
            documents = self.create_embedding(text=text['content'], category=category)

            if not documents['status']:  # Si no se obtuvieron los pedazos con metadatos.
                return documents

            # Se agrega el texto dividido como incrustaciones a la base de datos.
            self.__db.add_documents(documents['content'])

            return {'status': True, 'message': f'Se ha actualizado el entrenamiento {category}.'}

        except Exception as error:
            return {'status': False, 'message': f'Ocurrió un error al actualizar el entrenamiento: {str(error)}.'}

    def load_categories(self):
        """
        Método encargado de obtener y retornar una lista de la colecciones (entrenamientos) que se encuentran
        disponibles en la base de datos.

        Returns:
            dict: un diccionario con el estado, mensaje y resultado de la operación.
                - 'status' (bool): Estado de la operación.
                - 'message' (str): Mensaje de éxito o error.
                - 'content' (list): Lista con los entrenamientos.
        """
        try:
            # Se obtienen todos los documentos de la base de datos.
            all_docs = self.__db.get(include=['metadatas'])

            categories = set()

            # Se filtran los resultados con base a sus metadatos.
            for metadata in all_docs['metadatas']:
                if metadata and "category" in metadata:
                    categories.add(metadata["category"])

            return {'status': True, 'message': 'Se logró obtener la lista de los entrenamientos',
                    'content': list(categories)}

        except Exception as error:
            return {'status': False, 'message': f'Ocurrió un erro al obtener los entrenamientos: {str(error)}.',
                    'content': []}

    def db_query(self, query, category, k):
        """
        Método encargado de realizar una consulta a la base de datos con la finalidad de retornar documentos
        relevantes para lo solicitado.

        Args:
            query (str): Consulta a la base de datos.
            category (str): Nombre de la colección (entrenamiento).
            k (int): Número de coincidencias a obtener en la consulta.

        Returns:
            dict: un diccionario con el estado, mensaje y resultado de la operación.
                - 'status' (bool): Estado de la operación.
                - 'message' (str): Mensaje de éxito o error.
                - 'content' (list): Lista con los resultados de la consulta.
        """
        try:
            if not category in self.__collections:  # Si el entrenamiento no existe
                return {'status': False, 'message': 'El entrenamiento seleccionado no se encuentra registrado.'}

            # Se obtiene el resultado de la consulta a la base de datos.
            results = self.__db.similarity_search(query, k=k, filter={"category": category})

            if not results:  # Si no se encontraron coincidencias.
                return {'status': False, 'message': 'No se encontraron resultados para la consulta.'}

            # Se retorna la lista con las coincidencias
            return {'status': True, 'message': f'Se obtuvieron un total de {len(results)} resultados',
                    'content': [res.page_content for res in results]}

        except Exception as error:
            return {'status': False, 'message': f'Ocurrió un error al consultar la base de datos: {str(error)}.'}

    def get_collections(self):
        """
        Método encargado de retornar la lista de colecciones disponibles en la base de datos.
        """
        return self.__collections
