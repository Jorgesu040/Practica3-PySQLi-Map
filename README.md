# PySQLi-Automator

**PySQLi-Automator** es una herramienta desarrollada en Python para la detección y explotación automatizada de vulnerabilidades de Inyección SQL (SQL Injection) en bases de datos MySQL.

Diseñada con fines educativos y para mi asignatura de Introducción a la Seguridad Informática, permite a los usuarios verificar la seguridad de parámetros GET/POST en aplicaciones web y, en caso de detectar una vulnerabilidad, extraer información de la base de datos de forma interactiva y sencilla.

## Características

* **Tipos de detecciones**: Capacidad para detectar vulnerabilidades mediante:
  * **Error-Based**: Análisis de mensajes de error devueltos por MySQL.
  * **Boolean-Based**: Comparación de respuestas TRUE/FALSE.
  * **OR-Based**: Detección basada en inyecciones lógicas `OR 1=1`.
* **Enumeración Automática**: Cálculo automático del número de columnas en consultas `UNION SELECT`.
* **Identificación de Columnas**: Detección automática de columnas visibles para la extracción de datos.
* **Exfiltración Optimizada**: Uso de funciones de agrupación (`group_concat`) para extraer tablas completas en una sola petición HTTP.
* **Modo Interactivo**: Consola tipo SQLMap para navegar por bases de datos, tablas y columnas.
* **Reporting**: Generación de reportes detallados en formato Markdown.

## Requisitos

* Python 3.x
* Librería `requests`

## Instalación

1. Clona el repositorio:

    ```bash
    git clone https://github.com/Jorgesu040/Practica3-PySQLi-Map
    cd PySQLi-Automator
    ```

2. Instala las dependencias:

    ```bash
    pip install requests
    ```

## Uso

```bash
python3 Script.py -u <URL_OBJETIVO> -p <PARAMETRO> [opciones]
```

### Argumentos

* `-h`: Para lanzar un pequeño manual de uso y algún ejemplo
* `-u, --url`: URL objetivo completa (ej: `http://sitio.com/vuln.php`)
* `-p, --param`: Nombre del parámetro vulnerable a probar (ej: `id`)
* `-c, --cookies`: (Opcional) Cookies de sesión (ej: `'PHPSESSID=abc; security=low'`)
* `-e, --extra`: (Opcional) Parámetros extra necesarios para la petición (ej: `'Submit=Submit'`)

## Ejemplos de Ejecución

### 1. DVWA (Damn Vulnerable Web App), se incluye reporte de ejemplo en repositorio
 
```bash
python3 Script.py -u "http://192.168.1.105/vulnerabilities/sqli/" -p id -e "Submit=Submit" -c 'PHPSESSID=52qq03bni36bq92qkdhjeloc86;security=low'
```

### 2. Panel de Administración de la VM m87

```bash
python3 Script.py -u "http://192.168.1.54/admin/backup/" -p id
```

### 3. Ejemplo Básico PHP (Parámetro 'name') sobre Web for Pentester

```bash
python3 Script.py -u "http://192.168.1.66/sqli/example1.php/" -p name
```

### 4. Ejemplo con ID Numérico sobre Web for Pentester

```bash
python3 Script.py -u "http://192.168.1.66/sqli/example5.php" -p id
```

## Aviso Legal

Esta herramienta ha sido desarrollada con fines educativos y para pruebas de seguridad en entornos autorizados. El uso de esta herramienta contra objetivos sin previo consentimiento es ilegal. No me hago responsable del mal uso que se pueda dar a este software.
