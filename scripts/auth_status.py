import json
from _auth_local import store
if __name__=='__main__':print(json.dumps(store().status(),sort_keys=True))
