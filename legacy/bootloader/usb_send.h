#include <stdio.h>
static void send_response(usbd_device *dev, uint8_t *buf) {
  if (dev != NULL) {
    while (usbd_ep_write_packet(dev, ENDPOINT_ADDRESS_IN, buf, 64) != 64) {
    }
  } else {
    memcpy(i2c_data_out, buf, 64);
    i2c_slave_send_ex(64);
  }
}
static void send_msg_success(usbd_device *dev) {
  uint8_t response[64];
  memzero(response, sizeof(response));
  // response: Success message (id 2), payload len 0
  memcpy(response,
         // header
         "?##"
         // msg_id
         "\x00\x02"
         // msg_size
         "\x00\x00\x00\x00",
         9);
  send_response(dev, response);
}

static void send_msg_failure(usbd_device *dev, uint8_t code) {
  uint8_t response[64];
  memzero(response, sizeof(response));
  // response: Failure message (id 3), payload len 2
  memcpy(response,
         // header
         "?##"
         // msg_id
         "\x00\x03"
         // msg_size
         "\x00\x00\x00\x02"
         // code field id
         "\x08",
         10);
  // assign code value
  response[10] = code;
  send_response(dev, response);
}

extern uint8_t se_state;
static void send_msg_features(usbd_device *dev) {
  uint8_t response[256];
  memzero(response, sizeof(response));

  // response: Features message (id 17), payload len 26
  //           - vendor = "onekey.so"
  //           - major_version = VERSION_MAJOR
  //           - minor_version = VERSION_MINOR
  //           - patch_version = VERSION_PATCH
  //           - bootloader_mode = True
  //           - firmware_present = True/False
  //           - model = "1"
  //           ? fw_version_major = version_major
  //           ? fw_version_minor = version_minor
  //           ? fw_version_patch = version_patch
  const bool firmware_present = firmware_present_new();
  const image_header *current_hdr = (const image_header *)FLASH_FWHEADER_START;
  uint32_t version = firmware_present ? current_hdr->version : 0;

  // clang-format off
  const uint8_t feature_bytes[] = {
    0x0a,  // vendor field
    0x09,  // vendor length
    'o', 'n', 'e', 'k', 'e', 'y', '.', 's', 'o',
    0x10, VERSION_MAJOR,
    0x18, VERSION_MINOR,
    0x20, VERSION_PATCH,
    0x28, 0x01, // bootloader_mode
    0x90, 0x01, // firmware_present field
    firmware_present ? 0x01 : 0x00,
    0xaa, 0x01, // model field
    0x01,      // model length
    '1',
  };

  const uint8_t version_bytes[] = {
    // fw_version_major
    0xb0, 0x01, version & 0xff,
    // fw_version_minor
    0xb8, 0x01, (version >> 8) & 0xff,
    // fw_version_patch
    0xc0, 0x01, (version >> 16) & 0xff,
  };

  uint8_t battery_level[] = {
    0xc0, 0x20, 0x00
  };

  if(battery_cap==0xff){
    battery_level[2]=0x0f;
  }else{
    battery_level[2]=battery_cap;
  }

  uint8_t product[]={
    0xca, 0x20, 0x09,'c','l','a','s','s','i','c','1','s',
  };


  uint8_t onekey_device_type[]={
    0xc0, 0x25, 0x01,
  };
  uint8_t onekey_se_type[]={
    0xc8, 0x25, 0x00,
  };
  uint8_t se_version[3+8]={
    0xf2, 0x25, 0x0,
  };
  uint8_t se_build_id[3+8]={
    0x82, 0x26, 0x0,
  };
  uint8_t se_hash[3+32]={
    0xfa, 0x25, 0x0,
  };
  uint8_t boot_version[3+8]={
    0xe2, 0x25, 0x0,
  };
  uint8_t boot_hash[3+32]={
    0xea, 0x25, 0x0,
  };
  uint8_t firmware_version[3+8]={
    0x8a, 0x26, 0x0,
  };
  uint8_t firmware_hash[3+32]={
    0x92, 0x26, 0x00,
  };

  char *data = NULL;
  uint8_t se_ver_len = 0, se_build_id_len = 0, se_hash_len = 0;
  uint8_t boot_version_len = 0, boot_hash_len = 0;
  uint8_t firmware_version_len=0, firmware_hash_len = 0;

  // se version
  if(se_state == THD89_STATE_APP) {
    data = se_get_version();
    se_ver_len = strlen(data);
    se_version[2] = se_ver_len;
    memcpy(se_version+3, (uint8_t *)data, se_ver_len);
    se_ver_len+=3;

    // se build id
    data = se_get_build_id();
    se_build_id_len = strlen(data);
    se_build_id[2] = se_build_id_len;
    memcpy(se_build_id+3, (uint8_t *)data, se_build_id_len);
    se_build_id_len+=3;

    // se hash
    se_hash_len = 32 + 3;
    se_hash[2] = 32;
    memcpy(se_hash+3, se_get_hash(), 32);
  } else {
    se_ver_len = 3;
    se_build_id_len = 3;
    se_hash_len = 3;
  }

  // boot version
  boot_version_len = strlen((VERSTR(VERSION_MAJOR) "." VERSTR(VERSION_MINOR) "." VERSTR(
                       VERSION_PATCH)));
  boot_version[2] = boot_version_len;
  memcpy(boot_version+3, (uint8_t *)(VERSTR(VERSION_MAJOR) "." VERSTR(VERSION_MINOR) "." VERSTR(
                       VERSION_PATCH)), boot_version_len);
  boot_version_len+=3;

  // boot hash
  boot_hash[2] = 32;
  boot_hash_len = 3+32;
  sha256_Raw(FLASH_PTR(FLASH_BOOT_START), FLASH_BOOT_LEN, boot_hash+3);
  sha256_Raw(boot_hash+3, 32, boot_hash+3);

  // onekey_version
  if(firmware_present) {
    // firmware version
    uint32_t onekey_version = current_hdr->onekey_version;
    char firm_ver[16] = {0};
    sprintf(firm_ver,  "%d.%d.%d", (uint8_t)(onekey_version & 0xff), (uint8_t)((onekey_version >> 8) & 0xff), (uint8_t)((onekey_version >> 16) & 0xff));
    firmware_version_len = strlen(firm_ver);
    firmware_version[2] = firmware_version_len;
    memcpy(firmware_version+3, (uint8_t *)firm_ver, firmware_version_len);
    firmware_version_len+=3;

    // firmware hash
    firmware_hash[2] = 32;
    firmware_hash_len = 3+32;
    memcpy(firmware_hash+3, get_firmware_hash(current_hdr), 32);
  } else {
    firmware_version_len=3;
    firmware_hash_len=3;
  }

  int len =  sizeof(feature_bytes) + (firmware_present ? sizeof(version_bytes) : 0) + sizeof(battery_level)
    + sizeof(product) + sizeof(onekey_device_type) + sizeof(onekey_se_type) + se_ver_len + se_build_id_len + se_hash_len
    + boot_version_len + boot_hash_len + firmware_version_len + firmware_hash_len;
  uint8_t header_bytes[] = {
    // header
    '?', '#', '#',
    // msg_id
    0x00, 0x11,
    // msg_size
    0x00, 0x00, 0x00, len,
  };

  // clang-format on

  uint32_t offset = 0;

  memcpy(response, header_bytes, sizeof(header_bytes));
  offset += sizeof(header_bytes);
  memcpy(response + offset, feature_bytes, sizeof(feature_bytes));
  offset += sizeof(feature_bytes);
  if (firmware_present) {
    memcpy(response + offset, version_bytes, sizeof(version_bytes));
    offset += sizeof(version_bytes);
  }

  memcpy(response + offset, battery_level, sizeof(battery_level));
  offset += sizeof(battery_level);

  memcpy(response + offset, product, sizeof(product));
  offset += sizeof(product);

  memcpy(response + offset, onekey_device_type, sizeof(onekey_device_type));
  offset += sizeof(onekey_device_type);

  memcpy(response + offset, onekey_se_type, sizeof(onekey_se_type));
  offset += sizeof(onekey_se_type);

  memcpy(response + offset, se_version, se_ver_len);
  offset += se_ver_len;

  memcpy(response + offset, se_build_id, se_build_id_len);
  offset += se_build_id_len;

  memcpy(response + offset, se_hash, se_hash_len);
  offset += se_hash_len;

  memcpy(response + offset, boot_version, boot_version_len);
  offset += boot_version_len;

  memcpy(response + offset, boot_hash, boot_hash_len);
  offset += boot_hash_len;

  memcpy(response + offset, firmware_version, firmware_version_len);
  offset += firmware_version_len;

  memcpy(response + offset, firmware_hash, firmware_hash_len);

  uint8_t bt_pkg[256] = {0};
  const uint8_t *pkg = response;
  uint8_t packet_num = 0;
  uint8_t packet_len = 0;
  while (len) {
    if (packet_num == 0) {
      if (!dev) {
        memcpy(bt_pkg, pkg, 64);
      } else {
        send_response(dev, (uint8_t *)pkg);
      }
      len -= 64;
      pkg += 64;
    } else {
      memzero(packet_buf, sizeof(packet_buf));
      packet_buf[0] = '?';
      packet_len = len > 63 ? 63 : len;
      memcpy(packet_buf + 1, pkg, packet_len);
      pkg += packet_len;
      len -= packet_len;
      if (!dev) {
        memcpy(bt_pkg + 64 * packet_num, packet_buf, 64);
      } else {
        send_response(dev, packet_buf);
      }
    }
    packet_num++;
  }
  if (!dev) {
    memcpy(i2c_data_out, bt_pkg, 64 * packet_num);
    i2c_slave_send_ex(64 * packet_num);
  }
}

static void send_msg_buttonrequest_firmwarecheck(usbd_device *dev) {
  uint8_t response[64];
  memzero(response, sizeof(response));
  // response: ButtonRequest message (id 26), payload len 2
  //           - code = ButtonRequest_FirmwareCheck (9)
  memcpy(response,
         // header
         "?##"
         // msg_id
         "\x00\x1a"
         // msg_size
         "\x00\x00\x00\x02"
         // data
         "\x08"
         "\x09",
         11);
  send_response(dev, response);
}
