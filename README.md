# Process-Hollowing
This is a Process Hollowing POC in CPP

This is a simple CPP program for Process Hollowing.
-

Usage:

Process Hollowing.exe [Host_Process_File] [Injectet_File]

-- Host_Process_File - PE file wich will serve as the host process for the Injectet File.

-- Injectet_File - PE file wich will be injectet in to the host process.


Notes:

The 64 bit version works only with 64 bit host process and a 64 bit Injected PE. The same goes for the 32 bit version, needs 32 bit Host and PE.
