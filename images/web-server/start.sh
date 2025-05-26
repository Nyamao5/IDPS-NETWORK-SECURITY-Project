#!/bin/bash

# Start services
service apache2 start
service vsftpd start
service ssh start

# Keep container running
tail -f /dev/null