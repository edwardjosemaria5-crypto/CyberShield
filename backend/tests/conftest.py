import os
import sys
import tempfile

# Ensure backend root directory is on sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Use a throwaway SQLite file for the whole pytest session so the test
# database never touches the development database (cybershield.db).
_test_data_dir = tempfile.mkdtemp(prefix="cybershield-pytest-")
os.environ.setdefault(
    "CYBERSHIELD_DATABASE_URL",
    f"sqlite:///{os.path.join(_test_data_dir, 'test.db')}",
)