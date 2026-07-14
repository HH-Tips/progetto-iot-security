#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Errore: Questo script deve essere eseguito come root (es. 'sudo ./script.sh')" >&2
    exit 1
fi

tools/setup_network.sh
systemctl enable tftpd.service
systemctl restart tftpd.service

FIRMWARE=$1

if [ $# -lt 1 ]; then
    FIRMWARE="fmk/new-firmware.bin"
else
    echo "Firmware Override"
fi

dimensione=$(du -sh "$FIRMWARE" | cut -f1)
if [ "$dimensione" = "3,9M" ]; then
    echo "Cutting Firmware"
    dd if=$FIRMWARE of=/dev/shm/new-firmware_cut.bin bs=1 skip=131584
    cp /dev/shm/new-firmware_cut.bin /srv/tftp/new-firmware.bin
else
    cp $FIRMWARE /srv/tftp/new-firmware.bin
fi

.venv/bin/python -m tools.firmware_loader

tools/reset_network.sh
# systemctl stop tftpd.service
# systemctl disable tftpd.service
