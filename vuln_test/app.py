from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/")
def home():
    return "Vulnerable Test App"

# XSS vulnerable endpoint
@app.route("/xss")
def xss():
    name = request.args.get("name", "")
    return f"<h1>Hello {name}</h1>"

# SQL injection vulnerable endpoint
@app.route("/sqli")
def sqli():
    user_id = request.args.get("id", "")

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, username TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin')")

    query = f"SELECT * FROM users WHERE id = '{user_id}'"

    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return str(result)
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
