************************************************************************
Overview
************************************************************************
This application is an example of multithreaded device identification.

************************************************************************
Installation
************************************************************************
make: build application
make install: install application in src/bin directory

Notes:
build is dynamic by default.
Set STATIC=1 for static build.
Set DEBUG=1 to get debug info.
Set DPI_SDK to the ixEngine SDK path

************************************************************************
Usage
************************************************************************
Usage:
        pcap_device_identifier [options] pcap_files|interface

Options:
        --dpi_config <key>=<value>    Set ixEngine configuration value
        --dev_config <key>=<value>    Set libqmdevice configuration value
        --live                        Live capture from interface instead of pcap_files.
                                      By default tries the first interface if none given
        --csv <file>                  Set output CSV file path (default: ./output.csv)


************************************************************************
Environment variables
************************************************************************
This application is linked to libqmdevice and ixEngine libraries.

In case of dynamic building, you may need to set LD_LIBRARY_PATH

Example:
sudo LD_LIBRARY_PATH=$DPI_SDK/lib:../../lib  ./bin/pcap_device_identifier --live eth0
