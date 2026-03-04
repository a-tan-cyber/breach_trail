#!/bin/bash

#Check if the current user is root, if not exit

if [ "$(whoami)" != 'root' ]; then
	echo "Must run as R00T; exiting..."
	exit
fi

#Allow the user to specify the filename, check if the file exists

read -p 'Enter the File you want to analyze: ' USERFILE

if [ -f "$USERFILE" ]; then
	echo "$USERFILE exists; proceeding... "
else
	echo "$USERFILE does not exist; please provide a valid file..."
fi

# Attempt to extract network traffic; if found, display to the user the location and size

bulk_extractor -q $USERFILE -o BULK

if [ -f BULK/packets.pcap ]; then
	echo "[+][+] packets.pcap Found in BULK [Size: $(ls -lh BULK | grep packets.pcap | awk '{print $5}')]"
else
	echo 'PCAP not found'
fi