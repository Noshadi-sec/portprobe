import socket
from typing import List, Dict, Any


class Scanner:
    """Minimal port scanner with service fingerprinting."""

    def __init__(self, host: str, timeout: float = 2.0):
        """Initialize scanner with target host.

        Args:
            host: Target hostname or IP address
            timeout: Connection timeout in seconds

        Raises:
            ValueError: If host is empty or timeout is negative
        """
        if not host or not isinstance(host, str):
            raise ValueError("host must be a non-empty string")
        if timeout <= 0:
            raise ValueError("timeout must be a positive number")
        self.host = host
        self.timeout = timeout

    def scan(self, ports: List[int]) -> Dict[int, Dict[str, Any]]:
        """Scan specified ports and attempt service detection.

        Args:
            ports: List of port numbers to scan

        Returns:
            Dict mapping port number to scan results

        Raises:
            ValueError: If ports list is empty or contains invalid ports
        """
        if not ports:
            raise ValueError("ports list cannot be empty")
        if not isinstance(ports, list):
            raise ValueError("ports must be a list")
        for port in ports:
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError(f"invalid port number: {port}")

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
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, port))
            sock.close()
            return {"status": "open", "service": None}
        except socket.timeout:
            return {"status": "filtered", "service": None}
        except ConnectionRefusedError:
            return {"status": "closed", "service": None}
        except socket.gaierror as e:
            return {"status": "error", "error": f"DNS resolution failed: {str(e)}"}
        except OSError as e:
            return {"status": "error", "error": f"Connection error: {str(e)}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
