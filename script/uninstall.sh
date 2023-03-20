#!/usr/local/bin/bash

set -e

DIR=$1
if [ "${DIR}" = "" ]; then
	DIR=/usr/local
fi

[ -e /usr/sbin/kldxref ] || exit 1

[ ! -f /boot/modules/hammer2.ko ] || /bin/rm /boot/modules/hammer2.ko
/usr/sbin/kldxref /boot/modules

[ ! -f ${DIR}/sbin/hammer2 ] || /bin/rm ${DIR}/sbin/hammer2
[ ! -f ${DIR}/sbin/newfs_hammer2 ] || /bin/rm ${DIR}/sbin/newfs_hammer2
[ ! -f ${DIR}/sbin/mount_hammer2 ] || /bin/rm ${DIR}/sbin/mount_hammer2
[ ! -f ${DIR}/sbin/fsck_hammer2 ] || /bin/rm ${DIR}/sbin/fsck_hammer2
# XXX rmdir ${DIR}/sbin if empty

[ ! -f ${DIR}/man/man8/hammer2.8 ] || /bin/rm ${DIR}/man/man8/hammer2.8
[ ! -f ${DIR}/man/man8/hammer2.8.gz ] || /bin/rm ${DIR}/man/man8/hammer2.8.gz
[ ! -f ${DIR}/man/man8/newfs_hammer2.8 ] || /bin/rm ${DIR}/man/man8/newfs_hammer2.8
[ ! -f ${DIR}/man/man8/newfs_hammer2.8.gz ] || /bin/rm ${DIR}/man/man8/newfs_hammer2.8.gz
[ ! -f ${DIR}/man/man8/mount_hammer2.8 ] || /bin/rm ${DIR}/man/man8/mount_hammer2.8
[ ! -f ${DIR}/man/man8/mount_hammer2.8.gz ] || /bin/rm ${DIR}/man/man8/mount_hammer2.8.gz
[ ! -f ${DIR}/man/man8/fsck_hammer2.8 ] || /bin/rm ${DIR}/man/man8/fsck_hammer2.8
[ ! -f ${DIR}/man/man8/fsck_hammer2.8.gz ] || /bin/rm ${DIR}/man/man8/fsck_hammer2.8.gz
# XXX rmdir ${DIR}/man/man8 if empty

echo "uninstall success"
