#!/bin/bash

set -ex

UBUNTU_ARCHIVE=http://archive.ubuntu.com/ubuntu/pool/main/l/linux-hwe-6.5/

KERNEL_IMAGE=linux-image-unsigned-6.5.0-41-generic_6.5.0-41.41~22.04.2_amd64
KERNEL_HEADERS=linux-headers-6.5.0-41-generic_6.5.0-41.41~22.04.2_amd64
KERNEL_MODULES=linux-modules-6.5.0-41-generic_6.5.0-41.41~22.04.2_amd64

VERSION=6.5.0-41-generic
VMLINUZ_FILE="vmlinuz-$VERSION"

APT_REQUIREMENTS="unar python3-pip liblzo2-dev qemu-system netcat-openbsd"
echo "Installing required apt packages: $APT_REQUIREMENTS"
sudo apt install $APT_REQUIREMENTS

PIP_REQUIREMENTS="marin-m/vmlinux-to-elf nclib"
echo "Installing required pip packages: $PIP_REQUIREMENTS"
pip3 install --upgrade git+https://github.com/marin-m/vmlinux-to-elf
pip3 install nclib

mkdir images &> /dev/null || true
pushd ./images

if [[ ! -f "./vmlinuz" || ! -f "./vmlinux" ]]; then
    wget "$UBUNTU_ARCHIVE$KERNEL_IMAGE.deb"
    unar "./$KERNEL_IMAGE.deb"

    pushd "./$KERNEL_IMAGE"
        unar "data.tar"

        pushd  ./data/boot
            cp $VMLINUZ_FILE ../../../vmlinuz
        popd
    popd

    rm "$KERNEL_IMAGE.deb"
    rm -r "$KERNEL_IMAGE"

    echo "Got Ubuntu vmlinuz!"

    vmlinux-to-elf ./vmlinuz ./vmlinux

    echo "Got Ubuntu vmlinux!"

else
    echo "vmlinuz and vmlinux already exist. Skipping download and extraction."
fi

wget "$UBUNTU_ARCHIVE$KERNEL_HEADERS.deb"

echo "Installing Headers..."
sudo apt install "./$KERNEL_HEADERS.deb"
rm "./$KERNEL_HEADERS.deb"

if [[ ! -f "./bullseye.img" ]]; then
    wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh
    chmod +x ./create-image.sh
    echo "Creating debian image"
    ./create-image.sh -d bullseye
    sudo rm -r bullseye
    rm ./create-image.sh

    mkdir mnt &> /dev/null || true
    sudo mount ./bullseye.img ./mnt

    # Add unpriv user
    echo "user::1000:1000:user:/home/user:/bin/bash" | sudo tee -a ./mnt/etc/passwd
    sudo mkdir ./mnt/home/user

    # Enable rc.local for module loading
    sudo ln -s /etc/systemd/system/rc-local.service ./mnt/etc/systemd/system/multi-user.target.wants/rc-local.service
    sudo ln -s /lib/systemd/system/rc-local.service ./mnt/etc/systemd/system/rc-local.service

    cat <<EOF | sudo tee ./mnt/etc/rc.local
#!/bin/bash
insmod /root/dbg.ko || true
EOF
    sudo chmod +x ./mnt/etc/rc.local

    # Add flag file
    echo "flag{privesc_successful}" | sudo tee ./mnt/flag
    sudo chmod 600 ./mnt/flag

    # Add kernel modules
    wget "http://archive.ubuntu.com/ubuntu/pool/main/l/linux-hwe-6.5/$KERNEL_MODULES.deb"
    mkdir linux-modules
    ar x "./$KERNEL_MODULES.deb" --output linux-modules

    pushd linux-modules
        unzstd data.tar.zst
        unar data.tar
    popd

    sudo rm -r ./mnt/lib/modules || true
    sudo cp -r "./linux-modules/data/lib/modules" ./mnt/lib/modules/

    sudo rm -r ./mnt/boot || true
    sudo cp -r "./linux-modules/data/boot" ./mnt/
    sudo depmod -a -F ./mnt/boot/System.map-$VERSION -b ./mnt $VERSION
    sudo umount ./mnt

    rm -r mnt
    rm -r ./linux-modules
    rm -r "./$KERNEL_MODULES.deb"
else
    echo "debian image already exist. Skipping..."
fi

echo "Done!"
