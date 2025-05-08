FreeBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## Requirements

+ FreeBSD 13.x / 14.x

+ src tree under /usr/src

## Build

        $ cd freebsd_hammer2
        $ make

## Install

        $ cd freebsd_hammer2
        $ make install

## Uninstall

        $ cd freebsd_hammer2
        $ make uninstall

## Bugs

+ VOP\_READDIR implementation is known to not work with some user space libraries on 32 bit platforms.
