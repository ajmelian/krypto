# Krypto

Krypto es un controlador de **cifrado**, **descifrado** e **inspección** de documentos mediante **XChaCha20-Poly1305**. La clave de cifrado se deriva de:

* Un *pepper* global del sistema.
* El identificador persistente (*persistentId*) que Cl\@ve devuelve tras la autenticación.

Este enfoque garantiza que solo el usuario autenticado con el mismo *persistentId* pueda descifrar los documentos.

---

## Tabla de contenidos

* [Características](#características)
* [Requisitos](#requisitos)
* [Instalación](#instalación)
* [Variables de entorno](#variables-de-entorno)
* [Uso](#uso)

  * [Comandos](#comandos)
  * [Ejemplos](#ejemplos)
* [Seguridad y cumplimiento](#seguridad-y-cumplimiento)
* [Contribuciones](#contribuciones)
* [Licencia](#licencia)
* [Autores](#autores)

---

## Características

* Cifrado y descifrado de archivos con **XChaCha20-Poly1305**.
* Derivación de clave usando *pepper* y *persistentId* para máxima seguridad.
* Inspección de archivos cifrados para verificar su validez.
* Desarrollado siguiendo pautas de **desarrollo seguro** y **clean code**.
* Código **adaptable** para cualquier proyecto, bajo las condiciones de la licencia.
* Interfaz de línea de comandos fácil de usar.

## Requisitos

* PHP **8.2** o superior con **ext-sodium** habilitado.
* Acceso a la CLI de PHP.
* Servicio Cl\@ve para obtener el *persistentId* de usuario.

## Instalación

1. Clona este repositorio:

   ```bash
   git clone https://github.com/tu-usuario/tu-repo.git
   cd tu-repo
   ```
2. Copia o mueve `Krypto.php` al directorio deseado.
3. Concede permisos de ejecución (opcional):

   ```bash
   chmod +x Krypto.php
   ```

## Variables de entorno

Antes de usar la herramienta, configura las siguientes variables de entorno:

* `KRYPT_PEPPER`: Cadena secreta (pepper) compartida por el sistema.
* `PERSISTENT_ID`: Identificador persistente del usuario proporcionado por Cl\@ve.

Por ejemplo:

```bash
export KRYPT_PEPPER="miPepperSecreto"
export PERSISTENT_ID="XYZ123456"
```

## Uso

### Comandos

| Acción    | Sintaxis                           | Descripción                                       |
| --------- | ---------------------------------- | ------------------------------------------------- |
| `encrypt` | `php Krypto.php encrypt <archivo>` | Cifra el archivo especificado.                    |
| `decrypt` | `php Krypto.php decrypt <archivo>` | Descifra el archivo cifrado.                      |
| `analyze` | `php Krypto.php analyze <archivo>` | Comprueba si el archivo está cifrado válidamente. |

### Ejemplos

```bash
# Cifrar un documento
php Krypto.php encrypt documento.txt

# Descifrar un documento
php Krypto.php decrypt documento.txt.encrypted

# Analizar un documento cifrado
php Krypto.php analyze documento.txt.encrypted
```

## Seguridad y cumplimiento

### Tiempo de ruptura sin `PERSISTENT_ID`

Romper el cifrado sin disponer del `persistentId` ni del *pepper* requiere, en la práctica, un ataque de fuerza bruta contra la clave de 32 bytes derivada por Argon2id con parámetros moderados (aprox. 0,7 s y 256 MiB por derivación en CPU de 2.8 GHz). Incluso intentando un espacio de 2³² posibles *persistentId* llevaría en torno a **95 años** en un único CPU, y valores mayores resultan inviables (billones de años).

### Exclusividad de acceso

La clave simétrica solo se genera a partir de `pepper | persistentId`. Sin el mismo `persistentId` obtenido por Cl\@ve, ni acceso al pepper global, ningún atacante puede derivar la misma clave. Por tanto, **solo el usuario autenticado** que encriptó el documento puede descifrarlo.

### Política “Only-4-your-eyes”

Criptográficamente, XChaCha20-Poly1305 con clave única por usuario satisface la confidencialidad exclusiva: nadie más dispone de la clave. Para un cumplimiento organizativo completo, se recomienda acompañar con registros de acceso y auditorías.

### Cumplimiento GDPR (Art. 32) y NIS2 (Art. 21)

* **GDPR** exige “seudonimización y cifrado de datos personales” como medida técnica apropiada. Krypto proporciona cifrado de última generación para datos en reposo, cumpliendo este requisito, aunque GDPR también demanda gestión de claves, DPIA y procesos de notificación.
* **NIS2** prescribe medidas técnicas apropiadas, incluyendo cifrado, para gestionar riesgos en sistemas de información. Krypto aporta la capa criptográfica exigida, pero se debe complementar con planes de respuesta a incidentes, gestión de vulnerabilidades y formación de personal.

## Contribuciones

¡Todas las contribuciones son bienvenidas! Por favor, envía pull requests o abre *issues* para sugerir mejoras.

## Licencia

Este proyecto está bajo la **Licencia Pública General GNU**. Consulta el archivo [LICENSE](LICENSE) para más detalles.

## Autores

* **Aythami Melián Perdomo** ([ajmelper@gmail.com](mailto:ajmelper@gmail.com))
