import socket
from typing import List, Dict, Any


class Scanner:
    """Minimal port scanner with service fingerprinting."""

    def __init__(self, host: str, timeout: float = 2.0):
        """Initialize scanner with target host.

        Args:
            host: Target hostname or IP address
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.timeout = timeout

    def scan(self, ports: List[int]) -> Dict[int, Dict[str, Any]]:
        """Scan specified ports and attempt service detection.

        Args:
            ports: List of port numbers to scan

        Returns:
            Dict mapping port number to scan results
        """
        results = {}
        for port in ports:
            results[port] = self._probe_port(port)
        return results

    def _probe_port(self, port: int) -> Dict[str, Any]:
        """Attempt to connect to a single port.

        Args:
            port: Port number to probe

        Returns:
            Dict with status and service info
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((self.host, port))
            return {"status": "open", "service": None}
        except (socket.timeout, ConnectionRefusedError):
            return {"status": "closed", "service": None}
        except Exception as e:
            return {"status": "error", "error": str(e)}
        finally:
            sock.close()
