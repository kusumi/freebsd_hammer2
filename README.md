FreeBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## About

+ HAMMER2 file system for FreeBSD

## Requirements

+ Recent FreeBSD

    + Compiles and tested with -CURRENT

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

## Bugs

+ VOP\_READDIR implementation is known to not work with some user space libraries on 32 bit platforms.

## Notes

+ Tags are merely for packaging, nothing directly to do with file system version.

+ [makefs](https://github.com/kusumi/makefs) supports HAMMER2 image creation from a directory contents.
