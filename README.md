# speedwire
Wireshark Lua dissector for SMA devices

Thus Lua dissector for Wireshark helps in analyzing issues with SMA devices using the SMA proprietary Speedwire protocol. By lack of specifications, this dissector has been developed mostly based on trial and error analysis of existing Wireshark captures and code snippets found in other tools like SBFspot, YASML, DeviceDiscovery,...

The various pcapng capture files allow you to play around with the dissector. They each illustrate a different aspect of the dissector:
- sbfspot.pcapng illustrates analysis using the SBFspot tool
- sma2.pcapng illustrates active power curtailment using the DataManager M 
- discover.pcapng illustrates device discovery

This project is still in a very early stage. If you have ideas for improvement or if you have additional documentation that you can share, help would be much appreciated!

Kind regards,
Guy Coen
