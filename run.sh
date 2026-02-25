#!/bin/bash
echo "Accensione monitor..."
konsole  --title "ECU MONITOR" -e "./bin/candump" &
sleep 1
echo "Avvio ECU..."
./bin/clusterA &
./bin/clusterB &
sleep 2
./bin/rpm &
./bin/spd &
./bin/motor &
./bin/trm &
echo "Avvio simulatore..."
./bin/pqc-ecusim

