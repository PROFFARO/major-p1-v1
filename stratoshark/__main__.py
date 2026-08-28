import sys
from pathlib import Path

# Auto-inject project virtualenv site-packages so joblib, sklearn, xgboost, duckdb are immediately available
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

_venv_site = _project_root / "ml_engine" / ".venv" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
if _venv_site.exists() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))

from stratoshark.app import run_app

if __name__ == "__main__":
    sys.exit(run_app())

