from _auth_local import store
if __name__=='__main__':
    store().revoke()
    print('All sessions revoked.')
