# Sample vulnerable Python for offline analysis
import pickle
import subprocess

API_KEY = "sk-live-abc123xyz789secret"
password = "SuperSecret123!"

def load_user(data):
    return pickle.loads(data)  # insecure deserialization

def run_cmd(user_input):
    eval(user_input)  # dangerous
    exec("print(1)")
    subprocess.call(user_input, shell=True)

def sql_query(name):
    query = "SELECT * FROM users WHERE name = '%s'" % name  # SQL injection pattern
    return query
