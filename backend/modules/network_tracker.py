from __future__ import annotations

import socket
from typing import Any

import psutil

from backend.services.process_service import ProcessService


class NetworkTracker:
    def __init__(self, process_service: ProcessService) -> None:
        self.process_service = process_service

    @staticmethod
    def _protocol_from_type(sock_type: int | None) -> str:
        if sock_type == socket.SOCK_DGRAM:
            return "udp"
        if sock_type == socket.SOCK_STREAM:
            return "tcp"
        return "unknown"

    def capture_process_connections(self, pid: int) -> list[dict[str, Any]]:
        process = self.process_service.get_process(int(pid))
        if process is None:
            return []

        process_name = self.process_service.safe_name(process)
        events: list[dict[str, Any]] = []

        try:
            connections = process.net_connections(kind="inet")
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            connections = []

        for connection in connections:
            remote_ip = ""
            remote_port = 0
            if connection.raddr:
                remote_ip = str(connection.raddr.ip)
                remote_port = int(connection.raddr.port)

            events.append(
                {
                    "pid": int(pid),
                    "process_name": process_name,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": str(connection.status or "UNKNOWN"),
                    "protocol": self._protocol_from_type(connection.type),
                    "metadata": {
                        "local_ip": str(connection.laddr.ip) if connection.laddr else "",
                        "local_port": int(connection.laddr.port) if connection.laddr else 0,
                    },
                }
            )

        return events
