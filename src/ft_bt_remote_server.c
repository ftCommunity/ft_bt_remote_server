/*
 * ft_bt_remote_server.c
 *
 */

/* TODO:
 * - config whether js device should always be present or only if actually
 *   connected to a remote control
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <linux/uinput.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/l2cap.h"
#include "lib/uuid.h"

#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/timeout.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"

#define ATT_CID 4

#define COLOR_OFF	"\x1B[0m"
#define COLOR_GREEN	"\x1B[0;92m"
#define COLOR_YELLOW	"\x1B[0;93m"
#define COLOR_BOLDWHITE	"\x1B[1;37m"

#define DEFAULT_NAME "BT Control Receiver"

static bool verbose = false;

struct server {
  // global server config
  int dev_id;
  int sec;
  uint8_t src_type;
  char *name;
  int quit;
  
  int fd;
  int uinput_fd;
  struct bt_att *att;
  struct gatt_db *db;
  struct bt_gatt_server *gatt;
};

int init_uinput_device(struct server *server) {
  struct uinput_user_dev dev;

  server->uinput_fd = open("/dev/input/uinput", O_RDWR);
  
  if(server->uinput_fd < 0) {
    server->uinput_fd = open("/dev/uinput", O_RDWR);

    if(server->uinput_fd < 0) {
      printf("Unable to open uinput device.\n"
	     "Perhaps 'modprobe uinput' required?\n");
      return EXIT_FAILURE;
    }
  }
  
  memset(&dev,0,sizeof(dev));
  strncpy(dev.name, server->name, UINPUT_MAX_NAME_SIZE);
  dev.id.bustype = BUS_BLUETOOTH;
  dev.id.version = 0x01;
  dev.absmin[ABS_X] = dev.absmin[ABS_Y] = -32768;
  dev.absmax[ABS_X] = dev.absmax[ABS_Y] =  32767;
  dev.absmin[ABS_RX] = dev.absmin[ABS_RY] = -32768;
  dev.absmax[ABS_RX] = dev.absmax[ABS_RY] =  32767;

  if(write(server->uinput_fd, &dev, sizeof(dev)) < sizeof(dev)) {
    printf("Registering device at uinput failed\n");
    return EXIT_FAILURE;
  }

  // the BT Remote only supports four axes
  if(ioctl(server->uinput_fd, UI_SET_EVBIT, EV_ABS) < 0) perror("setting EV_ABS");
  if(ioctl(server->uinput_fd, UI_SET_ABSBIT, ABS_X) < 0) perror("setting ABS_X");
  if(ioctl(server->uinput_fd, UI_SET_ABSBIT, ABS_Y) < 0) perror("setting ABS_Y");
  if(ioctl(server->uinput_fd, UI_SET_ABSBIT, ABS_RX) < 0) perror("setting ABS_RX");
  if(ioctl(server->uinput_fd, UI_SET_ABSBIT, ABS_RY) < 0) perror("setting ABS_RY");
  
  if(ioctl(server->uinput_fd, UI_DEV_CREATE) < 0) {
    perror("Create device");
    return EXIT_FAILURE;
  }
    
  return 0;
}

/* Create uinput output */
int do_uinput(int fd, unsigned short key, int pressed, 
	      unsigned short event_type) {
  struct input_event event;
  memset(&event, 0 , sizeof(event));

  gettimeofday(&event.time, NULL);
  event.type = event_type;
  event.code = key;
  event.value = pressed;
  
  if(write(fd,&event,sizeof(event)) != sizeof(event))
    perror("Writing event");

  // Separate sync event as some uinput implementations only support single
  // event writes.
  memset(&event, 0 , sizeof(event));
  event.type = EV_SYN;
  if(write(fd,&event,sizeof(event)) != sizeof(event))
    perror("Writing event sync");

  fdatasync(fd);

  return 1;
}

static void att_disconnect_cb(int err, void *user_data)
{
	printf("Device disconnected: %s\n", strerror(err));

	mainloop_quit();
}

static void att_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;

	printf(COLOR_YELLOW "%s" COLOR_BOLDWHITE "%s\n" COLOR_OFF, prefix,
									str);
}

static void gatt_debug_cb(const char *str, void *user_data)
{
	const char *prefix = user_data;

	printf(COLOR_GREEN "%s%s\n" COLOR_OFF, prefix, str);
}

static void confirm_write(struct gatt_db_attribute *attr, int err,
							void *user_data)
{
	if (!err)
		return;

	fprintf(stderr, "Error caching attribute %p - err: %d\n", attr, err);
	exit(1);
}

static void populate_gap_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *tmp;
	uint16_t appearance = 0x0000;
	uint8_t conn_prop[] = { 0x06, 0x00, 0x28, 0x00, 0x00, 0x00, 0xe8, 0x03 };
	uint8_t central_addr_res[] = { 0x00 };
	
	/* Add the GAP service */
	bt_uuid16_create(&uuid, 0x1800);
	service = gatt_db_add_service(server->db, &uuid, true, 9);

	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_READ,
						 BT_GATT_CHRC_PROP_READ, NULL, NULL, server);
	gatt_db_attribute_write(tmp, 0, (void *)server->name, strlen(server->name),
				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);

	/* Appearance */
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_READ,
						 BT_GATT_CHRC_PROP_READ, NULL, NULL, server);
	gatt_db_attribute_write(tmp, 0, (void *)&appearance, sizeof(appearance),
				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);

	/* Preferred Connection Parameters */
	bt_uuid16_create(&uuid, GATT_CHARAC_PERIPHERAL_PREF_CONN);
	tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_READ,
						  BT_GATT_CHRC_PROP_READ, NULL, NULL, server);
	gatt_db_attribute_write(tmp, 0, (void *)&conn_prop, sizeof(conn_prop),
				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);
	
	/* Central Address Resolution */
	bt_uuid16_create(&uuid, 0x2aa6);
	tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_READ,
						  BT_GATT_CHRC_PROP_READ, NULL, NULL, server);
	gatt_db_attribute_write(tmp, 0, (void *)&central_addr_res, sizeof(central_addr_res),
				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);

	gatt_db_service_set_active(service, true);
}

static void populate_gatt_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service;

	/* Add the GATT service */
	bt_uuid16_create(&uuid, 0x1801);
	service = gatt_db_add_service(server->db, &uuid, true, 1);

	gatt_db_service_set_active(service, true);
}

static void populate_devinfo_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *tmp;
	uint8_t manu_name_str[14] = "fischertechnik";
	uint8_t model_no_str[6] = "161943";
	uint8_t hw_rev_str[2] = "1";
	uint8_t fw_rev_str[8] = "1.48\0\0\0\0";
	uint8_t sys_id[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x45, 0x11 }; 
  
	/* Add the DEV_INFO service */
	bt_uuid16_create(&uuid, 0x180a);
	service = gatt_db_add_service(server->db, &uuid, true, 11);

	/* Manufacturer Name String */
	bt_uuid16_create(&uuid, GATT_CHARAC_MANUFACTURER_NAME_STRING);
	tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_READ,
						  BT_GATT_CHRC_PROP_READ, NULL, NULL, server);
	gatt_db_attribute_write(tmp, 0, (void *)&manu_name_str, sizeof(manu_name_str),
				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);

	/* Model Number String */
	bt_uuid16_create(&uuid, GATT_CHARAC_MODEL_NUMBER_STRING);
	tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_READ,
						  BT_GATT_CHRC_PROP_READ, NULL, NULL, server);
	gatt_db_attribute_write(tmp, 0, (void *)&model_no_str, sizeof(model_no_str),
				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);

	/* Hardware Revision String */
	bt_uuid16_create(&uuid, GATT_CHARAC_HARDWARE_REVISION_STRING);
	tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_READ,
						  BT_GATT_CHRC_PROP_READ, NULL, NULL, server);
	gatt_db_attribute_write(tmp, 0, (void *)&hw_rev_str, sizeof(hw_rev_str),
				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);

	/* Firmware Revision String */
	bt_uuid16_create(&uuid, GATT_CHARAC_FIRMWARE_REVISION_STRING);
	tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_READ,
						  BT_GATT_CHRC_PROP_READ, NULL, NULL, server);
	gatt_db_attribute_write(tmp, 0, (void *)&fw_rev_str, sizeof(fw_rev_str),
				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);

	/* System ID */
	bt_uuid16_create(&uuid, GATT_CHARAC_SYSTEM_ID);
	tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_READ,
						  BT_GATT_CHRC_PROP_READ, NULL, NULL, server);
	gatt_db_attribute_write(tmp, 0, (void *)&sys_id, sizeof(sys_id),
				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);

	gatt_db_service_set_active(service, true);
}

static void batt_read_cb(struct gatt_db_attribute *attrib,
			     unsigned int id, uint16_t offset,
			     uint8_t opcode, struct bt_att *att,
			     void *user_data)
{
  printf("BATT RD\n");
	struct server *server = user_data;
	uint8_t value = 100;
	gatt_db_attribute_read_result(attrib, id, 0, &value, 1);
}

static void batt_read_cfg_cb(struct gatt_db_attribute *attrib,
			     unsigned int id, uint16_t offset,
			     uint8_t opcode, struct bt_att *att,
			     void *user_data)
{
  printf("BATT CFG RD\n");
	struct server *server = user_data;
	uint8_t value[2] = { 0x00, 0x00 };
	gatt_db_attribute_read_result(attrib, id, 0, value, 2);
}

static void batt_read_fmt_cb(struct gatt_db_attribute *attrib,
			     unsigned int id, uint16_t offset,
			     uint8_t opcode, struct bt_att *att,
			     void *user_data)
{
  printf("BATT FMT RD\n");
	struct server *server = user_data;
	uint8_t value[] = { 0x04, 0x00, 0xad, 0x27, 0x01, 0x06, 0x01 };
	gatt_db_attribute_read_result(attrib, id, 0, value, 7);
}

static void batt_write_cfg_cb(struct gatt_db_attribute *attrib,
			      unsigned int id, uint16_t offset,
			      const uint8_t *value, size_t len,
			      uint8_t opcode, struct bt_att *att,
			      void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	printf("BATT CFG WR %x/%x\n", value[0], value[1]);
	//	gatt_db_attribute_write(attrib, 0, (void *)value, 2,
	//				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);

 done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void populate_batt_service(struct server *server)
{
        bt_uuid_t uuid;
	struct gatt_db_attribute *service, *tmp;

	/* Add the BATT service */
	bt_uuid16_create(&uuid, 0x180f);
	service = gatt_db_add_service(server->db, &uuid, true, 5);

	/* BATT Measure */
	bt_uuid16_create(&uuid, 0x2a19);
	tmp = gatt_db_service_add_characteristic(service, &uuid,
			 BT_ATT_PERM_READ,
			 BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
			 batt_read_cb, NULL, server);

	bt_uuid16_create(&uuid, GATT_CHARAC_FMT_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
			BT_ATT_PERM_READ,
			batt_read_fmt_cb,
			NULL, server);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
			BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
			batt_read_cfg_cb,
			batt_write_cfg_cb, server);

	gatt_db_service_set_active(service, true);
}

static uint128_t bt_remote_base_uuid = {
  .data = { 0x2e,0x58,0x00,0x00,0xc5,0xc5,0x11,0xe6,0x9d,0x9d,0xce,0xc0,0xc9,0x32,0xce,0x01 }
};

static uint128_t bt_remote_uuid16(uint16_t u16) {
  bt_remote_base_uuid.data[2] = (u16 >> 8)&0xff;
  bt_remote_base_uuid.data[3] = (u16 >> 0)&0xff;
  return bt_remote_base_uuid;
}

static void populate_comm_channel_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *tmp;
	uint8_t comm_channel = 0;
	
	/* Add the COMMUNICATION CHANNEL service */
	bt_uuid128_create(&uuid, bt_remote_uuid16(0x2b3a));
	service = gatt_db_add_service(server->db, &uuid, true, 3);

	bt_uuid128_create(&uuid, bt_remote_uuid16(0x2de2));
	tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_READ,
	  BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
						 NULL, NULL, server);
	gatt_db_attribute_write(tmp, 0, (void *)&comm_channel, sizeof(comm_channel),
				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);
	
	gatt_db_service_set_active(service, true);
}

static void output_alert_read_cfg_cb(struct gatt_db_attribute *attrib,
				     unsigned int id, uint16_t offset,
				     uint8_t opcode, struct bt_att *att,
				     void *user_data)
{
        printf("OUTPUT ALERT CFG RD\n");
	struct server *server = user_data;
	uint8_t value[2] = { 0x00, 0x00 };
	gatt_db_attribute_read_result(attrib, id, 0, value, 2);
}

static void output_alert_write_cfg_cb(struct gatt_db_attribute *attrib,
				      unsigned int id, uint16_t offset,
				      const uint8_t *value, size_t len,
				      uint8_t opcode, struct bt_att *att,
				      void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	printf("OUTPUT ALERT CFG WR %x/%x\n", value[0], value[1]);
done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}

static void populate_output_alert_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *tmp;
	uint8_t output_alert = 0;
	
	/* Add the output alert service */
	bt_uuid128_create(&uuid, bt_remote_uuid16(0x2f9a));
	service = gatt_db_add_service(server->db, &uuid, true, 4);

	bt_uuid128_create(&uuid, bt_remote_uuid16(0x318e));
	tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_READ,
				 BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
				 NULL, NULL, server);
	gatt_db_attribute_write(tmp, 0, (void *)&output_alert, sizeof(output_alert),
				BT_ATT_OP_WRITE_REQ, NULL, confirm_write, NULL);
	
	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(service, &uuid,
			BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
			output_alert_read_cfg_cb,
			output_alert_write_cfg_cb, server);
	
	gatt_db_service_set_active(service, true);
}

static void output_write_cb(struct gatt_db_attribute *attrib,
			    unsigned int id, uint16_t offset,
			    const uint8_t *value, size_t len,
			    uint8_t opcode, struct bt_att *att,
			    void *user_data)
{
	struct server *server = user_data;
	uint8_t ecode = 0;

	if (!value || len != 1) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	uint16_t handle = gatt_db_attribute_get_handle(attrib);	
	// printf("OUTPUT WRITE %d %d\n", handle, value[0]);

	int axis = -1, factor = 1;
	if(handle == 0x24)      { axis = ABS_Y;  factor = -1; }
	else if(handle == 0x26)   axis = ABS_X;
	else if(handle == 0x28) { axis = ABS_RY; factor = -1; }
	else if(handle == 0x2a)   axis = ABS_RX;

	if(axis >= 0) 
	  do_uinput(server->uinput_fd, axis, factor*(int8_t)value[0]*256u, EV_ABS);
 
 done:	
	gatt_db_attribute_write_result(attrib, id, 0);
}
	
static void populate_output_service(struct server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *tmp;
	uint16_t i, uuids[] = { 0x3378, 0x358a, 0x3666, 0x37b0, 0 };
	  
	/* Add the output service */
	bt_uuid128_create(&uuid, bt_remote_uuid16(0x327e));
	service = gatt_db_add_service(server->db, &uuid, true, 9);

	for(i=0;uuids[i];i++) {
	  bt_uuid128_create(&uuid, bt_remote_uuid16(uuids[i]));
	  tmp = gatt_db_service_add_characteristic(service, &uuid, BT_ATT_PERM_WRITE,
			   BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
			   NULL, output_write_cb, server);
	}
	
	gatt_db_service_set_active(service, true);
}

static void populate_db(struct server *server)
{
	populate_gap_service(server);
	populate_gatt_service(server);
	populate_devinfo_service(server);
	populate_batt_service(server);
	populate_comm_channel_service(server);
	populate_output_alert_service(server);
	populate_output_service(server);
}

static int server_create(struct server *server, int fd)
{
	server->att = bt_att_new(fd, false);
	if (!server->att) {
		fprintf(stderr, "Failed to initialze ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_set_close_on_unref(server->att, true)) {
		fprintf(stderr, "Failed to set up ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_register_disconnect(server->att, att_disconnect_cb, NULL,
									NULL)) {
		fprintf(stderr, "Failed to set ATT disconnect handler\n");
		goto fail;
	}

	server->fd = fd;
	server->db = gatt_db_new();
	if (!server->db) {
		fprintf(stderr, "Failed to create GATT database\n");
		goto fail;
	}

	server->gatt = bt_gatt_server_new(server->db, server->att, 0);
	if (!server->gatt) {
		fprintf(stderr, "Failed to create GATT server\n");
		goto fail;
	}

	if (verbose) {
		bt_att_set_debug(server->att, att_debug_cb, "ATT: ", NULL);
		bt_gatt_server_set_debug(server->gatt, gatt_debug_cb,
							"SRV: ", NULL);
	}

	/* bt_gatt_server already holds a reference */
	populate_db(server);

	return 0;
fail:
	gatt_db_unref(server->db);
	bt_att_unref(server->att);

	return -1;
}

static void server_destroy(struct server *server)
{
  if(server->gatt)
    bt_gatt_server_unref(server->gatt);

  if(server->db)
    gatt_db_unref(server->db);

  if(server->att)
    bt_att_unref(server->att);
}

static void usage(void)
{
	printf("ft_bt_remote_server\n");
	printf("Usage:\n\tft_bt_remote_server [options]\n");

	printf("Options:\n"
		"\t-i, --index <id>\t\tSpecify adapter index, e.g. hci0\n"
		"\t-n, --name <name>\t\tThe device name to use\n"
		"\t-s, --security-level <sec>\tSet security level (low|"
								"medium|high)\n"
		"\t-t, --type [random|public] \tThe source address type\n"
		"\t-v, --verbose\t\t\tEnable extra logging\n"
		"\t-h, --help\t\t\tDisplay help\n");
}

static struct option main_options[] = {
	{ "index",		1, 0, 'i' },
	{ "name",		1, 0, 'n' },
	{ "security-level",	1, 0, 's' },
	{ "type",		1, 0, 't' },
	{ "verbose",		0, 0, 'v' },
	{ "help",		0, 0, 'h' },
	{ }
};

static int l2cap_le_att_listen_and_accept(bdaddr_t *src, int sec,
							uint8_t src_type)
{
	int sk, nsk;
	struct sockaddr_l2 srcaddr, addr;
	socklen_t optlen;
	struct bt_security btsec;
	char ba[18];

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Failed to create L2CAP socket");
		return -1;
	}

	/* Set up source address */
	memset(&srcaddr, 0, sizeof(srcaddr));
	srcaddr.l2_family = AF_BLUETOOTH;
	srcaddr.l2_cid = htobs(ATT_CID);
	srcaddr.l2_bdaddr_type = src_type;
	bacpy(&srcaddr.l2_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0) {
		perror("Failed to bind L2CAP socket");
		goto fail;
	}

	/* Set the security level */
	memset(&btsec, 0, sizeof(btsec));
	btsec.level = sec;
	if (setsockopt(sk, SOL_BLUETOOTH, BT_SECURITY, &btsec,
							sizeof(btsec)) != 0) {
		fprintf(stderr, "Failed to set L2CAP security level\n");
		goto fail;
	}

	if (listen(sk, 10) < 0) {
		perror("Listening on socket failed");
		goto fail;
	}

	printf("Waiting for connection ...\n");

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);
	nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
	if (nsk < 0) {
		perror("Accept failed");
		goto fail;
	}

	ba2str(&addr.l2_bdaddr, ba);
	printf("Connect from %s\n", ba);
	close(sk);

	return nsk;

fail:
	close(sk);
	return -1;
}

static void signal_cb(int signum, void *user_data) {
  struct server *server = user_data;

  switch (signum) {
  case SIGINT:
  case SIGTERM:
    printf("Caught signal, stopping service ...\n");
    mainloop_quit();
    server->quit = 1;
    break;
  default:
    break;
  }
}

static int server_init(struct server *server)
{

  int fd;
  bdaddr_t src_addr;

  if (server->dev_id == -1)
    bacpy(&src_addr, BDADDR_ANY);
  else if (hci_devba(server->dev_id, &src_addr) < 0) {
    perror("BT device doesn't exist");
    return EXIT_FAILURE;
  }

  fd = l2cap_le_att_listen_and_accept(&src_addr, server->sec, server->src_type);
  if (fd < 0) {
    fprintf(stderr, "Failure accepting att l2cap connection\n");
    return EXIT_FAILURE;
  }

  if(server_create(server, fd) < 0) {
    fprintf(stderr, "Failure creating server\n");
    return EXIT_FAILURE;
  }

  return 0;
}

static int btle_set_advertising_data(int dd, char *name)
{
  struct hci_request rq;
  uint8_t cp[32];

  memset(cp, 0, sizeof(cp));
  cp[0] = strlen(name)+5;
  cp[1] = 0x02; cp[2] = 0x01; cp[3] = 0x06;   // length, type, flags
  cp[4] = strlen(name)+1; cp[5] = 0x09;       // length, type
  memcpy(cp+6, name, strlen(name));           // name
  
  memset(&rq, 0, sizeof(rq));
  rq.ogf    = OGF_LE_CTL;
  rq.ocf    = OCF_LE_SET_ADVERTISING_DATA;
  rq.cparam = cp;
  rq.clen   = sizeof(cp);

  if (hci_send_req(dd, &rq, 1000) < 0) 
    return -1;

  return 0;
}

static int btle_set_advertising_parms(int dd)
{
  struct hci_request rq;
  le_set_advertising_parameters_cp cp = {
    .min_interval = 0x20,  // 20ms
    .max_interval = 0x20,  // 20ms
    .advtype = 0,
    .own_bdaddr_type = 0,
    .direct_bdaddr_type = 0,
    .direct_bdaddr = *BDADDR_ANY,
    .chan_map = 7,
    .filter = 0
  };
  
  memset(&rq, 0, sizeof(rq));
  rq.ogf    = OGF_LE_CTL;
  rq.ocf    = OCF_LE_SET_ADVERTISING_PARAMETERS;
  rq.cparam = (void*)&cp;
  rq.clen   = sizeof(cp);

  if (hci_send_req(dd, &rq, 1000) < 0) 
    return -1;

  return 0;
}

/* set the BDADDR of a TI chipset */
static int ti_set_addr(int dd, bdaddr_t *addr)
{
  uint8_t cp[] = {
    addr->b[5], addr->b[4], addr->b[3], 
    addr->b[2], addr->b[1], addr->b[0] };

  struct hci_request rq;
  memset(&rq, 0, sizeof(rq));
  rq.ogf    = OGF_VENDOR_CMD;
  rq.ocf    = 0x0006;
  rq.cparam = (void*)cp;
  rq.clen   = sizeof(cp);

  if (hci_send_req(dd, &rq, 1000) < 0) 
    return -1;

  return 0;
}

static int ble_init(struct server *server)
{
  int dd;
  struct hci_dev_info di;
  struct hci_version ver;
  char ba[18];
  
  int dev = (server->dev_id == -1)?0:server->dev_id;

  dd = hci_open_dev(dev);
  if (dd < 0) {
    fprintf(stderr, "Can't open device hci%d: %s (%d)\n",
	    dev, strerror(errno), errno);
    return EXIT_FAILURE;
  }

  if(hci_devinfo(dev, &di) < 0) {
    fprintf(stderr, "Can't get device info for hci%d: %s (%d)\n",
	    dev, strerror(errno), errno);
    hci_close_dev(dd);
    return EXIT_FAILURE;
  }

  // check if address is from LNT range
  if((di.bdaddr.b[5] != 0x10) || (di.bdaddr.b[4] != 0x45) ||
     (di.bdaddr.b[3] != 0xf8))  {
    ba2str(&di.bdaddr, ba);
    printf("WARNING, BDADDR is not from LNT range: %s\n", ba);

    // check for chip vendor
    if (hci_read_local_version(dd, &ver, 1000) < 0) {
      fprintf(stderr, "Can't read version info for hci%d: %s (%d)\n",
	      dev, strerror(errno), errno);
      hci_close_dev(dd);
      return EXIT_FAILURE;
    }

    // manufacturer 13 is TI which is the vendor of the chip in the TXT
    if(ver.manufacturer != 13) {
      fprintf(stderr, "Can't adjust BDADDR for hci%d on %s (%d)\n",
	      dev, bt_compidtostr(ver.manufacturer), ver.manufacturer);

	hci_close_dev(dd);
      return EXIT_FAILURE;
    }

    // adjust bdaddr
    bdaddr_t new_addr = di.bdaddr;
    new_addr.b[5] = 0x10;
    new_addr.b[4] = 0x45;
    new_addr.b[3] = 0xf8;
      
    ba2str(&new_addr, ba);
    printf("Setting BDADDR: %s\n", ba);

    if ( ti_set_addr(dd, &new_addr) < 0) {
      fprintf(stderr, "Can't set new BDADDR on hci%d: %s (%d)\n",
	      dev, strerror(errno), errno);
      hci_close_dev(dd);
      return EXIT_FAILURE;
    }
  }
  
  // set device name
  printf("Setting name: %s\n", server->name);
  if (hci_write_local_name(dd, server->name, 1000) < 0) {
    fprintf(stderr, "Can't write local name for hci%d: %s (%d)\n",
	    dev, strerror(errno), errno);
    hci_close_dev(dd);
    return EXIT_FAILURE;
  }

  // set advertise enable off. Ignore any problem as e.g. an error is
  // returned ig advertise is already off
  hci_le_set_advertise_enable(dd, 0, 1000);

  // Set Advertising Data
  if ( btle_set_advertising_data(dd, server->name) < 0) {
    fprintf(stderr, "Can't set advertising data for hci%d: %s (%d)\n",
	    dev, strerror(errno), errno);
    hci_close_dev(dd);
    return EXIT_FAILURE;
  }
  
  // LE Set Advertising Parameters
  if ( btle_set_advertising_parms(dd) < 0) {
    fprintf(stderr, "Can't set advertising parameters for hci%d: %s (%d)\n",
	    dev, strerror(errno), errno);
    hci_close_dev(dd);
    return EXIT_FAILURE;
  }
  
  // set advertise enable on
  if (hci_le_set_advertise_enable(dd, 1, 1000) < 0) {
    fprintf(stderr, "Can't set advertise enable on for hci%d: %s (%d)\n",
	    dev, strerror(errno), errno);
    hci_close_dev(dd);
    return EXIT_FAILURE;
  }

  
  hci_close_dev(dd);
	
  return 0;
}

int main(int argc, char *argv[])
{
	int opt;
	sigset_t mask;

	struct server server;
	memset(&server, 0, sizeof(server));
	
	server.dev_id = -1;
	server.sec = BT_SECURITY_LOW;
	server.src_type = BDADDR_LE_PUBLIC;
	server.name = strdup(DEFAULT_NAME);
	
	while ((opt = getopt_long(argc, argv, "+hvs:t:n:i:",
						main_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return EXIT_SUCCESS;
		case 'v':
			verbose = true;
			break;
		case 'n':
		        strcpy(server.name, optarg);
			break;
		case 's':
			if (strcmp(optarg, "low") == 0)
				server.sec = BT_SECURITY_LOW;
			else if (strcmp(optarg, "medium") == 0)
				server.sec = BT_SECURITY_MEDIUM;
			else if (strcmp(optarg, "high") == 0)
				server.sec = BT_SECURITY_HIGH;
			else {
				fprintf(stderr, "Invalid security level\n");
				return EXIT_FAILURE;
			}
			break;
		case 't':
			if (strcmp(optarg, "random") == 0)
				server.src_type = BDADDR_LE_RANDOM;
			else if (strcmp(optarg, "public") == 0)
				server.src_type = BDADDR_LE_PUBLIC;
			else {
				fprintf(stderr,
					"Allowed types: random, public\n");
				return EXIT_FAILURE;
			}
			break;
		case 'i':
			server.dev_id = hci_devid(optarg);
			if (server.dev_id < 0) {
				perror("Invalid adapter");
				return EXIT_FAILURE;
			}

			break;
		default:
			fprintf(stderr, "Unknown option: %c\n", opt);
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv -= optind;
	optind = 0;

	if (argc) {
		usage();
		return EXIT_SUCCESS;
	}

	init_uinput_device(&server);

	while(! server.quit) {
	  mainloop_init();

	  if(ble_init(&server) == 0) {
	    server_init(&server);
	      
	    sigemptyset(&mask);
	    sigaddset(&mask, SIGINT);
	    sigaddset(&mask, SIGTERM);	
	    mainloop_set_signal(&mask, signal_cb, &server, NULL);

	    mainloop_run();

	    signal(SIGINT, SIG_DFL);
	    signal(SIGTERM, SIG_DFL);
	      
	    server_destroy(&server);
	  } else
	    sleep(1);
	}
	
	printf("Shutting down...\n");	  
	close(server.uinput_fd);

	return EXIT_SUCCESS;
}
