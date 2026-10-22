"""Tor controller for IP Rotator module (using stem)."""

from stem import Signal
from stem.control import Controller


class TorController:
    def __init__(self, host="127.0.0.1", control_port=9151, socks_port=9050):
        self.host = host
        self.control_port = control_port
        self.socks_port = socks_port

    def change_identity(self) -> tuple[bool, str]:
        """Send NEWNYM signal to Tor to get a new IP using stem."""
        try:
            
            with Controller.from_port(address=self.host, port=self.control_port) as controller:
                controller.authenticate() 
                controller.signal(Signal.NEWNYM)
                return True, "New identity requested. IP will change in a few seconds."
        except Exception as exc:
            return False, f"Error connecting to Tor: {exc}"