FreeBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## About

+ HAMMER2 file system for FreeBSD (read-only support)

+ Out-of-tree repository for https://github.com/freebsd/freebsd-src/pull/627

## Requirements

+ Recent FreeBSD

    + Compiles and tested with 14.0-CURRENT

    + Known to compile with 13.X-XXX, but untested

    + Does not compile with 12.X-XXX or below

+ FreeBSD src tree under /usr/src by default

## Build

        $ cd freebsd_hammer2
        $ make

## Install

        $ sudo bash -x ./script/install.sh

## Uninstall

        $ sudo bash -x ./script/uninstall.sh

## Ports

+ WIP at https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=267982

+ However I recommend directly using this repository as ports/pkg tend to be not uptodate with upstream.

## Notes

+ Write support is not planned for FreeBSD.

+ Tags are merely for packaging, nothing directly to do with file system version.

+ -CURRENT aka upstream FreeBSD is the only tier 1 support branch at the moment.
