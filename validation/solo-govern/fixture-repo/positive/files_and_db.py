import os
import shutil
import sqlite3
import subprocess


def purge(path):
    shutil.rmtree(path)


def remove_one(path):
    os.remove(path)


def drop_user(conn, uid):
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()


def run_shell(cmd):
    return subprocess.run(cmd, shell=True)
