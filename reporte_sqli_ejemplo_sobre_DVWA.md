# Reporte de SQL Injection

**Fecha:** 2025-12-14 13:42:11
**URL:** http://192.168.1.105/vulnerabilities/sqli/
**Parámetro vulnerable:** id
**Tipo de inyección:** comilla simple

## Bases de Datos (4)

### cdcol

#### Tablas (1)

##### cds

| titel | interpret | jahr | id |
|-------|-----------|------|----|
| Beauty | Ryuichi Sakamoto | 1990 | 1 |
| Goodbye Country (Hello Nightclub) | Groove Armada | 2001 | 4 |
| Glee | Bran Van 3000 | 1997 | 5 |

### dvwa

#### Tablas (2)

##### guestbook

| comment_id | comment | name |
|------------|---------|------|
| 1 | This is a test comment. | test |

##### users

| user_id | first_name | last_name | user | password | avatar |
|---------|------------|-----------|------|----------|--------|
| 1 | admin | admin | admin | 5f4dcc3b5aa765d61d8327deb882cf99 | dvwa/hackable/users/admin.jpg |
| 2 | Gordon | Brown | gordonb | e99a18c428cb38d5f260853678922e03 | dvwa/hackable/users/gordonb.jpg |
| 3 | Hack | Me | 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b | dvwa/hackable/users/1337.jpg |
| 4 | Pablo | Picasso | pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 | dvwa/hackable/users/pablo.jpg |
| 5 | Bob | Smith | smithy | 5f4dcc3b5aa765d61d8327deb882cf99 | dvwa/hackable/users/smithy.jpg |

### phpmyadmin

#### Tablas (8)

##### pma_bookmark

**Columnas:** id, dbase, user, label, query

##### pma_column_info

**Columnas:** id, db_name, table_name, column_name, comment, mimetype, transformation, transformation_options

##### pma_designer_coords

**Columnas:** db_name, table_name, x, y, v, h

##### pma_history

**Columnas:** id, username, db, table, timevalue, sqlquery

##### pma_pdf_pages

**Columnas:** db_name, page_nr, page_descr

##### pma_relation

**Columnas:** master_db, master_table, master_field, foreign_db, foreign_table, foreign_field

##### pma_table_coords

**Columnas:** db_name, table_name, pdf_page_number, x, y

##### pma_table_info

**Columnas:** db_name, table_name, display_field

### test

No se pudieron obtener las tablas.

