# ft_bt_remote_server

This tool implements a bluetooth le gatt server for the fischertechnik
TXT. It listens for incoming requests from the remote controller of
the fischertechnik BT Control Set and allows to use the remote
controller with the TXT.

The server creates a linux joystick input device and is compatible
with most linux applications that deal with joysticks. Due to the lack
of fire buttons on the remote controller the usablity as a generic
joystick replacement is rather limited.

The server modifies the local bluetooth address of the TXT to be
detected by the remote control. The OUI part of the bluetooth address
(the first three bytes) are temporarily changed to 10:45:F8 which
is the OUI of LNT, the maker of the BT Control Set. This change isn't
permanent and is reset once the TXT is rebooted.

The server can also be used on the Raspberry Pi3 and a script is also
taking care fot the temporary address change there. The server may
also be used on other Linux systems but a special tool may be needed
to change the bluetooth address there. The bdaddr tool from the bluez
framework is such a tool. Be careful, on some plattforms these changes
are permanent.
