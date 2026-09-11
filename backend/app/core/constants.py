#: Maximum accepted scan-target length in characters. The same bound applies
#: to the legacy module routes that accept user-controlled target/domain path
#: parameters (see app/api/routes) and to the POST /scan body contract.
MAX_TARGET_LENGTH = 2048

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389]
