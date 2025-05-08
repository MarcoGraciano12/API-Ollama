"""
Módulo para gestionar la instancia única de Ollama utilizando el patrón Singleton.

Este módulo asegura que solo haya una única instancia de la clase OllamaSingleton en la aplicación. El cliente Ollama
se inicializa solo cuando es necesario, optimizando recursos y garantizando consistencia en la conexión con Ollama.

El patrón Singleton asegura que las aplicaciones que requieren interacción con el modelo Ollama mantengan una única
instancia de la conexión durante toda la ejecución.
"""

# Importación de Módulos
import ollama


# Declaración de Clases
class OllamaSingleton:
    """
    Clase que implementa el patrón Singleton para la gestión de la instancia de Ollama.
    Garantiza que solo exista una instancia del cliente Ollama a lo largo de la ejecución del programa.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        """
        Crea o devuelve la única instancia del cliente Ollama.
        Si la instancia ya ha sido creada, devuelve la misma instancia.
        """
        try:
            if cls._instance is None:
                cls._instance = super(OllamaSingleton, cls).__new__(cls, *args, **kwargs)
                cls._instance.client = ollama  # Mantener la instancia única de Ollama.
        except Exception as error:
            print(f">>> ¡Error al manejar la instancia de Ollama: {error}!")
        finally:
            return cls._instance  # Retorna siempre la misma instancia.


# Ejemplo de Implementación
if __name__ == "__main__":
    # Se crea un objeto de la clase OllamaSingleton
    singleton_one = OllamaSingleton()

    # Se crea un segundo objeto de la clase OllamaSingleton
    singleton_two = OllamaSingleton()

    # Se verifica que tengan la misma instancia
    print(f"¿Son la misma instancia? {singleton_one is singleton_two}")