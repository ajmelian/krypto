<?php
/**
 * Krypto — controlador de **cifrado**, **descifrado** e **inspección** de documentos.
 *
 * Protege archivos mediante XChaCha20‑Poly1305 y una clave derivada de:
 *   — Un *pepper* global del sistema, y
 *   — El identificador persistente (persistentId) que Cl@ve devuelve tras la autenticación.
 *
 * Este método permite la exclusividad del desencriptado para la persona identificada a
 * través de Cl@ve que encriptó el documento.
 *
 * -----------------------------------------------------------------------------
 *  Copyright © 2025  Equipo‑Desarrollo
 *
 *  Este programa es software libre: usted puede redistribuirlo y/o modificarlo
 *  bajo los términos de la **Licencia Pública General GNU** publicada por la
 *  Free Software Foundation, ya sea la versión 3 de la Licencia, o (a su
 *  elección) cualquier versión posterior.
 *
 *  Este programa se distribuye con la esperanza de que sea útil, pero **SIN
 *  NINGUNA GARANTÍA**; ni siquiera la garantía implícita **de COMERCIABILIDAD o
 *  ADECUACIÓN PARA UN PROPÓSITO PARTICULAR**.  Consulte la Licencia Pública
 *  General GNU para más detalles.
 *
 *  Debería haber recibido una copia de la Licencia Pública General GNU junto con
 *  este programa.  Si no, véase <https://www.gnu.org/licenses/>.
 * -----------------------------------------------------------------------------
 *
 * ### Requisitos
 * * PHP **8.4** o superior
 * * Cl@ve 2.0 o superior (https://administracionelectronica.gob.es/ctt/clave)
 *
 * ### Uso desde la línea de comandos
 * ```bash
 * # Cifrar un PDF para un usuario autenticado con Cl@ve
 * php Krypto.php encrypt  /ruta/absoluta/archivo.pdf  MARA2025  <persistentId>
 *
 * # Descifrar un contenedor generado por esta herramienta
 * php Krypto.php decrypt  /ruta/absoluta/archivo.enc  MARA2025  <persistentId>
 *
 * # Analizar un archivo para comprobar si es un contenedor Krypto válido
 * php Krypto.php analyze  /ruta/absoluta/archivo.enc
 * ```
 *
 * ### Formato del contenedor (v2)
 * | Desplazamiento | Longitud | Descripción                             |
 * |--------------:|---------:|------------------------------------------|
 * | 0             | 1        | Versión (2)                              |
 * | 1             | 2        | Longitud del nombre original (uint16 BE) |
 * | 3             | variable | Nombre de fichero original (UTF‑8)       |
 * | —             | 16       | Sal de Argon2id                          |
 * | —             | 24       | Nonce AEAD (XChaCha20‑Poly1305)          |
 * | —             |   …      | Texto cifrado                            |
 *
 * El nombre final que se guarda en disco es el **SHA‑256** de todo el
 * contenedor más la extensión `.enc`, de modo que no revela nada sobre su
 * contenido.
 *
 * @package App\Crypto
 * @author  Aythami Melián Perdomo <ajmelper@gmail.com>
 * @version 1.0.0 (2025‑05‑11)
 * @copyright 2025  Aythami Melián Perdomo <ajmelper@gmail.com>
 * @license   GPL-3.0-or-later <https://www.gnu.org/licenses/gpl-3.0-standalone.html>
 */

declare(strict_types=1);

namespace App\Crypto;

final class Krypto
{
    /** @var int Versión actual del formato de contenedor */
    private const VERSION = 2;

    /** Parámetros Argon2id de libsodium (perfil "moderate") */
    private const KDF_OPS = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
    private const KDF_MEM = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
    private const KDF_ALG = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13;

    /** Longitudes fijas de campos */
    private const SALT_LEN  = SODIUM_CRYPTO_PWHASH_SALTBYTES;                     // 16 B
    private const NONCE_LEN = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES; // 24 B

    /**
     * Cifra un PDF y genera un contenedor `.enc` cuyo nombre es su propio SHA‑256.
     *
     * @param string $filePath      Ruta absoluta a un PDF legible.
     * @param string $pepper        Pepper global del sistema, almacenado fuera del repositorio.
     * @param string $persistentId  Identificador opaco y estable proporcionado por Cl@ve.
     *
     * @return string Ruta absoluta al archivo cifrado generado.
     *
     * @throws \InvalidArgumentException Si el archivo de entrada o los parámetros son inválidos.
     * @throws \RuntimeException         Si falla la escritura en disco.
     */
    public static function encrypt(string $filePath, string $pepper, string $persistentId): string
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            throw new \InvalidArgumentException("El archivo '$filePath' no existe o no es legible.");
        }
        if ($persistentId === '') {
            throw new \InvalidArgumentException('El parámetro persistentId no puede estar vacío.');
        }

        // — Leer el PDF fuente
        $pdfData  = file_get_contents($filePath);
        $fileName = basename($filePath);

        // — Derivar clave simétrica de 256 bits: Argon2id( pepper|"|"|pid, salt )
        $salt = random_bytes(self::SALT_LEN);
        $key  = sodium_crypto_pwhash(
            32,
            $pepper . '|' . $persistentId,
            $salt,
            self::KDF_OPS,
            self::KDF_MEM,
            self::KDF_ALG
        );

        // — Cifrar la carga útil
        $nonce      = random_bytes(self::NONCE_LEN);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($pdfData, '', $nonce, $key);
        sodium_memzero($key); // Borrar la clave de la memoria

        // — Construir contenedor: [ver|fnameLen|fname|salt|nonce|cipher]
        $container = pack('C', self::VERSION)
                  .  pack('n', strlen($fileName))
                  .  $fileName
                  .  $salt
                  .  $nonce
                  .  $ciphertext;

        // — Guardar en disco empleando su hash SHA‑256 como nombre
        $hash    = hash('sha256', $container);
        $outPath = dirname($filePath) . DIRECTORY_SEPARATOR . $hash . '.enc';
        if (file_put_contents($outPath, $container, LOCK_EX) === false) {
            throw new \RuntimeException("No se pudo escribir el archivo cifrado '$outPath'.");
        }
        return realpath($outPath);
    }

    /**
     * Descifra un contenedor creado por {@see encrypt()} y restaura el PDF original.
     * Se deben aportar el mismo pepper e identificador persistente usados en el cifrado.
     *
     * @param string $encPath       Ruta absoluta al archivo `.enc`.
     * @param string $pepper        Pepper global del sistema.
     * @param string $persistentId  Identificador opaco devuelto por el login de Cl@ve.
     *
     * @return string Ruta absoluta al PDF restaurado.
     *
     * @throws \InvalidArgumentException Si los parámetros son erróneos.
     * @throws \RuntimeException         Si el contenedor es inválido, las credenciales son incorrectas o falla la escritura.
     */
    public static function decrypt(string $encPath, string $pepper, string $persistentId): string
    {
        if ($persistentId === '') {
            throw new \InvalidArgumentException('El parámetro persistentId no puede estar vacío.');
        }

        $meta = self::parseHeader($encPath);
        if (!$meta['recognized']) {
            throw new \RuntimeException('El archivo no es un contenedor Krypto válido.');
        }
        if ($meta['version'] !== self::VERSION) {
            throw new \RuntimeException('Versión de contenedor no soportada: ' . $meta['version']);
        }

        // Extraer texto cifrado y volver a derivar la clave
        $cipher = substr($meta['raw'], $meta['headerLen']);
        $key    = sodium_crypto_pwhash(
            32,
            $pepper . '|' . $persistentId,
            $meta['salt'],
            self::KDF_OPS,
            self::KDF_MEM,
            self::KDF_ALG
        );

        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, '', $meta['nonce'], $key);
        sodium_memzero($key);
        if ($plain === false) {
            throw new \RuntimeException('Descifrado fallido (credenciales incorrectas o archivo dañado).');
        }

        $outPath = dirname($encPath) . DIRECTORY_SEPARATOR . $meta['fileName'];
        if (file_put_contents($outPath, $plain, LOCK_EX) === false) {
            throw new \RuntimeException("No se pudo escribir el PDF restaurado '$outPath'.");
        }
        return realpath($outPath);
    }

    /**
     * Comprueba de forma rápida si un archivo tiene la estructura de un contenedor Krypto.
     * **No** valida credenciales.
     *
     * @param string $encPath Ruta al archivo a analizar.
     *
     * @return array{
     *     recognized: bool,     // El encabezado coincide con el formato
     *     decryptable: bool,    // Hay texto cifrado tras el encabezado
     *     info: string          // Mensaje descriptivo
     * }
     */
    public static function analyze(string $encPath): array
    {
        $meta = self::parseHeader($encPath, false);
        if (!$meta['recognized']) {
            return [
                'recognized'   => false,
                'decryptable'  => false,
                'info'         => 'No se detecta firma Krypto.'
            ];
        }

        $lengthOk = filesize($encPath) > $meta['headerLen'];
        return [
            'recognized'  => true,
            'decryptable' => $lengthOk,
            'info'        => $lengthOk
                ? 'Contenedor Krypto v' . $meta['version'] . ' válido.'
                : 'Contenedor truncado (sin texto cifrado).'
        ];
    }

    /* ---------------------------------------------------------------- */
    /*                        Funciones internas                         */
    /* ---------------------------------------------------------------- */

    /**
     * Analiza la cabecera del contenedor y devuelve metadatos útiles.
     *
     * @param string $path       Archivo a examinar.
     * @param bool   $returnRaw  Si se debe incluir el contenido bruto en el resultado.
     *
     * @return array{
     *     recognized: bool,
     *     version?: int,
     *     headerLen?: int,
     *     fileName?: string,
     *     salt?: string,
     *     nonce?: string,
     *     raw?: string
     * }
     */
    private static function parseHeader(string $path, bool $returnRaw = true): array
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new \InvalidArgumentException("El archivo '$path' no existe o no es legible.");
        }
        $content = file_get_contents($path);
        if ($content === false || strlen($content) < 1 + 2 + self::SALT_LEN + self::NONCE_LEN) {
            return ['recognized' => false];
        }

        $offset  = 0;
        $version = ord($content[$offset]); $offset += 1;

        // Aceptamos versiones futuras como "reconocidas"; el llamador decidirá compatibilidad.
        $fnameLen = unpack('n', substr($content, $offset, 2))[1]; $offset += 2;
        if (strlen($content) < 3 + $fnameLen + self::SALT_LEN + self::NONCE_LEN) {
            return ['recognized' => false];
        }

        $fileName = substr($content, $offset, $fnameLen); $offset += $fnameLen;
        $salt     = substr($content, $offset, self::SALT_LEN);  $offset += self::SALT_LEN;
        $nonce    = substr($content, $offset, self::NONCE_LEN); $offset += self::NONCE_LEN;

        return [
            'recognized' => true,
            'version'    => $version,
            'headerLen'  => $offset,
            'fileName'   => $fileName,
            'salt'       => $salt,
            'nonce'      => $nonce,
            'raw'        => $returnRaw ? $content : null
        ];
    }
}

// ---------------------------------------------------------------------
//                             ENTORNO CLI                             
// ---------------------------------------------------------------------
if (php_sapi_name() === 'cli') {
    /**
     * Interfaz mínima de línea de comandos para utilizar el controlador sin
     * necesidad de un framework web.
     */
    $argv ??= [];
    if (($argc = $_SERVER['argc'] ?? 0) < 3) {
        fwrite(STDERR, "Uso:\n  php Krypto.php encrypt <filePath> <pepper> <persistentId>\n  php Krypto.php decrypt <encPath> <pepper> <persistentId>\n  php Krypto.php analyze <encPath>\n");
        exit(1);
    }

    [, $action] = $argv;

    try {
        switch ($action) {
            case 'encrypt':
                if ($argc !== 5) throw new \InvalidArgumentException('encriptado requiere de 3 parámetros.');
                [, , $file, $pepper, $pid] = $argv;
                $out = Krypto::encrypt($file, $pepper, $pid);
                echo "Encrypted: $out\n";
                break;

            case 'decrypt':
                if ($argc !== 5) throw new \InvalidArgumentException('desencriptado requiere de 3 parámetros.');
                [, , $file, $pepper, $pid] = $argv;
                $out = Krypto::decrypt($file, $pepper, $pid);
                echo "Decrypted: $out\n";
                break;

            case 'analyze':
                if ($argc !== 3) throw new \InvalidArgumentException('analisis requiere de 1 parámetro.');
                [, , $file] = $argv;
                $info = Krypto::analyze($file);
                echo ($info['recognized'] ? '✓ ' : '✗ ') . $info['info'] . "\n";
                break;

            default:
                throw new \InvalidArgumentException("Acción desconocida: '$action'.");
        }
    } catch (\Throwable $e) {
        fwrite(STDERR, $e->getMessage() . "\n");
        exit(1);
    }
}