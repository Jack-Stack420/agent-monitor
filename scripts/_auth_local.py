import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from auth import Store
def store():return Store(ROOT/'data/auth/auth.db')
