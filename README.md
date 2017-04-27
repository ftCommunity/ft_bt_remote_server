# fischertechnik BT Control Set server - ft_bt_remote_server

The fischertechnik BT Remote Server allows to use the remote control
unit (sender) of the fischertechnik BT Control Set to be used on a Linux
host like the fischertechnik TXT controller or the Raspberry Pi.

[Video](https://www.youtube.com/watch?v=5oSWWJYuSTQ)

This tool implements a bluetooth le gatt server. It listens for
incoming requests from the remote controller and presents it to the
underlying Linux system.

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
