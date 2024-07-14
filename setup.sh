#!/bin/bash

# Install dependencies
pip install -r req.txt

# Make the script executable
chmod +x Onedax_code_alpha_sniffer.py

# Copy the script to a directory in the user's PATH
cp Onedax_code_alpha_sniffer.py /usr/local/bin

echo "Installation complete."
