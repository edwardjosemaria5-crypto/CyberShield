from app.modules.ports.scanner import scan_ports_module


def run_ports_check(host: str):
    return scan_ports_module(host)
