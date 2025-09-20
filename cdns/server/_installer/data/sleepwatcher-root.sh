#!/bin/bash
echo "Executing file"

for file in /etc/cdns/sleepwatcher-root.d/*
do
    bash $file
done
