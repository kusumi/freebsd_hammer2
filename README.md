FreeBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## About

+ HAMMER2 file system for FreeBSD (read-only support)

+ FreeBSD port of DragonFly BSD's HAMMER2 file system

## Requirements

+ Recent FreeBSD

    + Compiles and tested with 14.0-CURRENT

    + Known to compile with 13.X-XXX, but untested

    + Does not compile with 12.X-XXX or below

+ FreeBSD src tree under /usr/src

+ Bash

## Build

        $ cd freebsd_hammer2
        $ make

## Install

        $ cd freebsd_hammer2
        $ make install

## Uninstall

        $ cd freebsd_hammer2
        $ make uninstall

## Ports

+ https://www.freshports.org/sysutils/hammer2

## Notes

+ Write support is not planned for FreeBSD.

+ Tags are merely for packaging, nothing directly to do with file system version.

+ -CURRENT aka upstream FreeBSD is the only tier 1 support branch at the moment.

+ [makefs(8) for Linux](https://github.com/kusumi/makefs) supports HAMMER2 image creation from a directory contents on Linux. There is currently no way to do this on FreeBSD.
