import getpass
from _auth_local import store

def main():
    first=getpass.getpass('New owner password (at least 14 characters): ')
    second=getpass.getpass('Repeat new password: ')
    if first!=second:raise SystemExit('Passwords do not match; unchanged.')
    try:store().set_password(first)
    except ValueError as exc:raise SystemExit(str(exc))
    print('Owner password set. All sessions revoked.')
if __name__=='__main__':main()
