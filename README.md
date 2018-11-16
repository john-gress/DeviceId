# DeviceId

************************************************************************
Overview
************************************************************************
This application is an example of multithreaded device identification.<br>

************************************************************************
## Installation

make: build application<br>
make install: install application in src/bin directory<br>

### Notes:
build is dynamic by default.<br>
Set STATIC=1 for static build.<br>
Set DEBUG=1 to get debug info.<br>
Set DPI_SDK to the ixEngine SDK path<br>

************************************************************************
## Usage:
        pcap_device_identifier [options] pcap_files|interface<br>

### Options:
        --dpi_config <key>=<value>    Set ixEngine configuration value<br>
        --dev_config <key>=<value>    Set libqmdevice configuration value<br>
        --live                        Live capture from interface instead of pcap_files.<br>
                                      By default tries the first interface if none given<br>
        --csv <file>                  Set output CSV file path (default: ./output.csv)<br>


************************************************************************
## Environment variables

This application is linked to libqmdevice and ixEngine libraries.<br>

In case of dynamic building, you may need to set LD_LIBRARY_PATH<br>

### Example:
sudo LD_LIBRARY_PATH=$DPI_SDK/lib:../../lib  ./bin/pcap_device_identifier --live eth0<br>
