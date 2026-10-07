import subprocess
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    # Deliberately vulnerable: a command built from user input.
    cmd = request.args.get("cmd")
    return subprocess.check_output(cmd, shell=True)


@app.route("/user")
def user():
    # Deliberately vulnerable: SQL built by string formatting.
    conn = sqlite3.connect("app.db")
    name = request.args.get("name")
    return str(conn.execute("SELECT * FROM users WHERE name = %s" % name).fetchall())
