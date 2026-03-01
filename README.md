# PQC-ECUSim
Modular C++ simulator for secure automotive ECU networks. Implements multi-node CAN comunications using [Vector SIL Kit](https://github.com/vectorgrp/sil-kit.git) and integrates post-quantum cryptography with liboqs.
## Overview
This project is a distributed ECU (Electronic Control Unit) simulator built with SilKit, designed to demonstrate secure intra-vehicle communication using Post-Quantum Cryptography (PQC) and traditional AES-256 encryption. The simulation models a vehicle powertrain dynamic, including throttle input, RPM calculation, engine torque (stress), speed, and an automatic transmission system.
### Currently simulated components
* Accelerator (pqc-ecusim): The primary user interface. Captures throttle input (0-100%) and broadcasts acceleration data every 50ms.
* RPM ECU: Calculates engine revolutions per minute based on throttle and load.
* Motor ECU: Simulates engine stress and torque (load).
* Speed (SPD) ECU: Calculates vehicle speed based on RPM and current gear.
* Auto Transmission (Auto_TRM): An automatic gearbox logic that manages gear shifts.
* Network Logger (candump): A dedicated participant that monitors all bus traffic, providing real-time terminal output and saving session logs to .txt for forensic analysis.
* [feature/pqc-cluster] Cluster Managers: dedicated participa
### Transport protocol 
The project implements a custom transport layer inspired by the ISO-TP (ISO 15765-2) protocol. It dynamically manages data segmentation using a specialized header:
* Adaptive Framing: Automatically switches between Standard CAN and CAN FD based on payload size.
* Protocol Features: Supports SingleFrame, FirstFrame, and ConsecutiveFrame logic to handle large cryptographic payloads across the CAN bus.
### Cryptographic architectures
#### Static Security (Main Branch)
All frames are encrypted through AES-256 with an hard-coded static key across all ECUs.
#### Post-Quantum Hybrid Clustering (feature/pqc-cluster Branch)
Individual KEM handshakes for every ECU pair (P2P) are too resource-intensive for automotive hardware. Conversely, a single global gateway key creates a Single Point of Failure (SPOF). In this project ECUs are grouped into Security Clusters (in this case a cluster of 3 and a cluster of 2) that performs a Kyber (PQC) KEM handshake to establish a shared secret within the group, utilizing [liboqs](https://github.com/open-quantum-safe/liboqs.git) for quantum-resistant key exchange.
## Requirements

## Installation

## Execution


