#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Errore: Questo script deve essere eseguito come root (es. 'sudo ./script.sh')" >&2
    exit 1
fi

tools/setup_network.sh
systemctl enable tftpd.service
systemctl restart tftpd.service

cp fmk/new-firmware.bin /srv/tftp/new-firmware.bin

.venv/bin/python -m tools.firmware_loader

tools/reset_network.sh
systemctl stop tftpd.service
systemctl disable tftpd.service
