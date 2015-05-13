#!/bin/bash

if [ "$1" != "" ]; then
    python CANSim.py
else
    echo Outputting to $1;
    python CANSim.py > $1;
fi
