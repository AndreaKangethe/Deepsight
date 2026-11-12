import os, tempfile
_d = tempfile.mkdtemp()
os.environ["ASIVM_DATABASE_URL"] = f"sqlite:///{_d}/t.db"
os.environ["ASIVM_SCHEDULER_ENABLED"] = "false"
os.environ["ASIVM_MODEL_DIR"] = f"{_d}/models"
os.environ["ASIVM_SECRET_KEY"] = "test-secret-key-with-enough-length-1234"
