# PV dissectors
Wireshark Lua dissectors for PV devices

Thus Lua dissector for Wireshark helps in analyzing issues with several PV devices. Currently, the following devices are supported:
- SMA inverters using the speedwire protocol
- SMA inverters using the SMA Data protocol
- Sungrow inverters

The various pcapng capture files allow you to play around with the dissectors. They each illustrate a different aspect of the dissector:
- sbfspot.pcapng illustrates analysis using the SBFspot tool
- sma2.pcapng illustrates active power curtailment using the DataManager M 
- discover.pcapng illustrates device discovery

This project is still in a very early stage. If you have ideas for improvement or if you have additional documentation that you can share, help would be much appreciated!

Kind regards,
Guy Coen

References:
[1] https://www.sma.de/fileadmin/content/global/Partner/Documents/sma_developer/SpeedwireDD-TI-en-10.pdf
[2] https://github.com/SBFspot/SBFspot/
[3] https://www.sma.de/fileadmin/content/global/Products/Documents/Monitoring_Systems/YASDI-10NE1106.pdf
