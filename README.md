FreeBSD [HAMMER2](https://gitweb.dragonflybsd.org/dragonfly.git/blob/HEAD:/sys/vfs/hammer2/DESIGN)
========

## About

+ HAMMER2 file system for FreeBSD (read-only support)

+ Out-of-tree repository for https://github.com/freebsd/freebsd-src/pull/627

## Requirements

+ Recent FreeBSD (only tested with 14.0-CURRENT)

+ FreeBSD src tree under /usr/src by default

## Build

        $ cd freebsd_hammer2
        $ make
        $ tree dist/
        dist/
        |-- bin
        |   |-- fsck_hammer2 -> ../../src/sbin/fsck_hammer2/fsck_hammer2
        |   |-- hammer2 -> ../../src/sbin/hammer2/hammer2
        |   |-- mount_hammer2 -> ../../src/sbin/mount_hammer2/mount_hammer2
        |   `-- newfs_hammer2 -> ../../src/sbin/newfs_hammer2/newfs_hammer2
        |-- kld
        |   `-- hammer2.ko -> ../../src/sys/fs/hammer2/hammer2.ko
        `-- man
            |-- fsck_hammer2.8 -> ../../src/sbin/fsck_hammer2/fsck_hammer2.8
            |-- hammer2.8 -> ../../src/sbin/hammer2/hammer2.8
            |-- mount_hammer2.8 -> ../../src/sbin/mount_hammer2/mount_hammer2.8
            `-- newfs_hammer2.8 -> ../../src/sbin/newfs_hammer2/newfs_hammer2.8

## Notes

+ Write support is not planned for FreeBSD.

+ Tags are merely for packaging, nothing directly to do with file system version.
