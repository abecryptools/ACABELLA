#!/bin/sh

docker build -t abeattacks .

echo "\n\n[*] Now run run_examples.py\n"

docker run -it abeattacks

