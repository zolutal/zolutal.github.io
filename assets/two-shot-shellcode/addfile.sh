#!/bin/bash

mkdir ./mnt
sudo mount ./images/bullseye.img ./mnt
sudo cp $1 ./mnt/root
sleep .5
sudo cp $1 ./mnt/home/user
sleep .5
sudo umount ./mnt
sleep .5
rmdir ./mnt
