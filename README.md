# Hermodr
Command line tool to stream Layer2/Layer3 network packages just like JDSU through the native operating system interface. Here are the customizable pieces of the network package.

*  Destination MAC (required)
* Source MAC (optional, deafult is the interface MAC)
* Destination IP (required)
* Source IP (optional, default: 0.0.0.0)
* Interface (required)
* Duration in seconds (default: 10)
* MTU size (default: 1000 bytes, at least give out 1000 bytes due to CPU bottleneck)
* Rate in Gbps (default: 1.0)
* VLAN ID (default: 0)
* DSCP value (default: 0)
* CoS value (default: 0)
* Config file path to send in stream (optional)


## Setting up Development Environment
A JSON library and some build related tools are needed for setting up the development environment and getting the build.
`sudo apt-get install libcjson1 libcjson-dev gcc cmake pkg-config`

Afterwards to get the executable create `build` directory and run `cmake .. && make -j4` to point out the top level CMake file as well as compiling it.