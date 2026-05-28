import sqlite3

conn = sqlite3.connect('cis_analyzer.db')
cursor = conn.execute("PRAGMA table_info(api_endpoints)")

print("COLUNAS DA TABELA 'api_endpoints':")
for col in cursor.fetchall():
    print(f"- {col[1]}")