MAM_MAGIC = b"MAM\x04"


def is_mam_compressed(data: bytes) -> bool:
    return len(data) >= 8 and data[:4] == MAM_MAGIC
