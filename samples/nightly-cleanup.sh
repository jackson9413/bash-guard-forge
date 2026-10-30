#!/bin/bash
LOGDIR=/var/log/app
BACKUP=/var/backups
cd $LOGDIR
find . -name '*.log' -mtime +30 -delete
tar -czf $BACKUP/logs.tar.gz $(ls *.log | head -20)
rm $LOGDIR/*.log
sed -i 's/verbose = true/verbose = false/' $LOGDIR/app.conf
which rsync
