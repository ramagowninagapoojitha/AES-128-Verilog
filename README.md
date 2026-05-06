# AES-128-Verilog
AES-128 Encryption &amp; Decryption in Verilog (RTL to GDS)
Project Overview

This project implements the AES-128 (Advanced Encryption Standard) algorithm in Verilog HDL with support for both encryption and decryption operations.

The design includes:

AES Encryption module
AES Decryption module
Top module with mode-based operation selection
FSM-based control architecture
Complete simulation verification using ModelSim
A single top module is used to perform both encryption and decryption using a mode control signal.
Features
AES-128 Encryption
AES-128 Decryption
Mode-based operation selection
Verilog HDL implementation
Finite State Machine (FSM) control
Key Expansion support
Synthesizable hardware design
Verified using standard AES test vectors
Simulation waveform verification
Mode Selection
Mode	Operation
0	Encryption
1	Decryption

Top Module Description

The top module integrates both encryption and decryption modules.

When mode = 0, the encryption module is enabled.
When mode = 1, the decryption module is enabled.

The design uses:

Common input interface
Shared AES key input
Single output interface





Simulation Test Vectors
Encryption Test

Plaintext
00112233445566778899aabbccddeeff

Key
000102030405060708090a0b0c0d0e0f

Expected Ciphertext
69c4e0d86a7b0430d8cdb78070b4c55a

Decryption Test
Ciphertext
69c4e0d86a7b0430d8cdb78070b4c55a

Key
000102030405060708090a0b0c0d0e0f

Expected Plaintext
00112233445566778899aabbccddeeff
Simulation Results

<img width="566" height="196" alt="output_transcript Window" src="https://github.com/user-attachments/assets/3092cc35-45ab-4f14-add5-7af4a1661323" />
<img width="1594" height="477" alt="output_waveform" src="https://github.com/user-attachments/assets/63db9c38-fb0e-4e27-81dd-452fab2315fc" />


How to Run

Compile Files
    AES.v
    INV_AES.v
    AES_TOP.v
    AES_TOP_tb.v
Run Simulation
   run -all

Expected Output

========== ENCRYPTION TEST ==========
Ciphertext = 69c4e0d86a7b0430d8cdb78070b4c55a

ENCRYPTION CORRECT

========== DECRYPTION TEST ==========
Plaintext = 00112233445566778899aabbccddeeff

DECRYPTION CORRECT


