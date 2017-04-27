#!/bin/sh
#
# Prepare TXT to act as a BT Control Receiver
#

NAME="BT Control Receiver"

hciconfig hci0 up
hciconfig hci0 name "$NAME"
hciconfig hci0 noscan

# Figure out the chip manufacturer as broadcom (R-PI3) needs
# to be re-initialized by the kernel after changing address. 
# We thus do the address change here in that case and not
# inside the driver application. The TXT's address is taken
# care for by the ft_bt_remote_server app itself.
BDADDR=`hciconfig hci0 | grep Address | cut -d' ' -f 3`
OID=`echo $BDADDR | cut -d':' -f 1-3`
if [ "$OID" != "10:45:F8" ]; then
    MANU=`hciconfig hci0 -a | grep "Manufacturer" | cut -d'(' -f2 | cut -d')' -f1`
    if [ "$MANU" = "15" ]; then
	echo "Adjusting BDADDR on Broadcom chipset ..." 
	# this is a broadcom chip and the address doesn't match
	# the LNT range. Try to change the address
	ID0=`echo $BDADDR | cut -d':' -f 4`
	ID1=`echo $BDADDR | cut -d':' -f 5`
	ID2=`echo $BDADDR | cut -d':' -f 6`
	CMD="0x"$ID2" 0x"$ID1" 0x"$ID0" 0xf8 0x45 0x10"
	hcitool cmd 0x3f 0x0001 $CMD
    fi
fi

hciconfig hci0 reset

ft_bt_remote_server -n "$NAME"
