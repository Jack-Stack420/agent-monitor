"""Set the Tailscale owner locally without echoing or logging the login."""
import getpass
from _auth_local import ROOT
from auth import set_tailscale_owner

def main():
    try:set_tailscale_owner(ROOT,getpass.getpass('Tailscale owner login (hidden): '))
    except (ValueError,OSError):raise SystemExit('Owner setup failed; check private local permissions and login.')
    print('Tailscale owner configured.')

if __name__=='__main__':main()
