#!/bin/bash
if command -v konsole >/dev/null; then
    TERMINAL="konsole -e"
elif command -v gnome-terminal >/dev/null; then
    TERMINAL="gnome-terminal --"
else
    TERMINAL="xterm -e"
fi
echo "Accensione monitor..."
$TERMINAL "./bin/candump" &
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

