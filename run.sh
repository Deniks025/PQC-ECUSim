#!/bin/bash
echo "Accensione monitor..."
konsole  --title "ECU RPM" -e "./bin/candump" &
sleep 1
echo "Avvio ECU..."
./bin/rpm &
./bin/spd &
./bin/motor &
./bin/trm &
sleep 2
echo "Avvio simulatore..."
./bin/pqc-ecusim

