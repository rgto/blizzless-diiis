import struct

data_hex = '0A-2D-1A-08-50-4C-41-54-49-4E-55-4D-2A-08-50-4C-41-54-49-4E-55-4D-48-01-58-B9-97-DB-CE-06-78-00-80-01-04-A0-01-14-A8-01-14-C8-01-0A-D0-01-01-12-00-1A-51-08-74-12-04-08-00-10-00-1A-31-08-FB-BB-BA-5A-10-8D-C2-E9-C8-05-18-8A-D0-F4-D4-0C-20-A9-8E-94-D9-06-28-A9-8E-94-D9-06-30-99-E0-AC-CF-07-38-BC-C4-BA-E4-03-40-82-B2-9F-C6-0F-48-01-20-72-38-01-48-00-50-01-58-00-6A-08-08-AF-B3-19-10-AF-B3-19-70-00-22-00-2A-00-32-21-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-3A-07-44-65-66-61-75-6C-74-42-0B-08-00-12-07-54-65-73-74-45-72-61-48-B9-97-DB-CE-06-52-3C-0A-04-08-00-18-01-0A-04-08-01-18-01-0A-04-08-02-18-01-0A-04-08-03-18-01-0A-04-08-04-18-01-0A-04-08-05-18-01-0A-04-08-06-18-01-0A-04-08-0A-18-01-0A-04-08-0F-18-01-0A-04-08-14-18-01-62-08-08-00-10-00-18-00-20-01-72-02-0A-00-7A-4D-0A-40-32-30-33-37-35-35-34-36-33-33-35-44-41-31-33-45-33-31-35-35-34-41-31-30-34-46-45-30-33-36-42-35-42-43-43-38-37-38-44-37-31-35-31-30-38-46-31-46-43-45-42-35-30-41-42-38-35-42-44-38-37-34-37-38-12-05-2E-61-63-68-75-1A-02-45-55-88-01-00-92-01-84-03-20-4F-6E-6C-69-6E-65-53-65-72-76-69-63-65-2E-53-65-61-73-6F-6E-2E-4E-75-6D-3D-31-20-4F-6E-6C-69-6E-65-53-65-72-76-69-63-65-2E-53-65-61-73-6F-6E-2E-53-74-61-74-65-3D-31-20-4F-6E-6C-69-6E-65-53-65-72-76-69-63-65-2E-4C-65-61-64-65-72-62-6F-61-72-64-2E-45-72-61-3D-31-20-4F-6E-6C-69-6E-65-53-65-72-76-69-63-65-2E-41-6E-6E-69-76-65-72-73-61-72-79-45-76-65-6E-74-2E-53-74-61-74-75-73-3D-31-20-43-68-61-6C-6C-65-6E-67-65-52-69-66-74-2E-43-68-61-6C-6C-65-6E-67-65-4E-75-6D-62-65-72-3D-31-20-4F-6E-6C-69-6E-65-53-65-72-76-69-63-65-2E-46-72-65-65-54-6F-50-6C-61-79-3D-54-72-75-65-20-4F-6E-6C-69-6E-65-53-65-72-76-69-63-65-2E-53-74-6F-72-65-2E-53-74-61-74-75-73-3D-31-20-4F-6E-6C-69-6E-65-53-65-72-76-69-63-65-2E-53-74-6F-72-65-2E-50-72-6F-64-75-63-74-43-61-74-61-6C-6F-67-44-69-67-65-73-74-3D-43-34-32-44-43-36-31-31-37-41-37-30-30-38-45-44-41-32-30-30-36-35-34-32-44-36-43-30-37-45-41-44-30-39-36-44-41-44-39-30-20-4F-6E-6C-69-6E-65-53-65-72-76-69-63-65-2E-53-74-6F-72-65-2E-50-72-6F-64-75-63-74-43-61-74-61-6C-6F-67-56-65-72-73-69-6F-6E-3D-36-33-33-35-36-35-38-30-30-33-39-30-33-33-38-30-30-30-20-4F-6E-6C-69-6E-65-53-65-72-76-69-63-65-2E-52-65-67-69-6F-6E-2E-49-64-3D-31'

data = bytes([int(b, 16) for b in data_hex.split('-')])

# InitialLoginData field names (from Notification.cs)
ILD_FIELDS = {
    1: 'game_account_settings', 2: 'hero_digests', 3: 'account_digest',
    4: 'guilds', 5: 'guild_invites', 6: 'seen_tutorials', 7: 'matchmaking_pool',
    8: 'eras', 9: 'logon_time', 10: 'content_licenses', 11: 'session_flags',
    12: 'outstanding_order', 13: 'unacknowledged_orders', 14: 'missing_entitlements',
    15: 'achievements_content_handle', 16: 'program_blacklist_fourccs',
    17: 'chat_restriction_content_license_id', 18: 'synced_vars'
}

def decode_varint(data, pos):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, pos

def decode_protobuf(data, field_names=None, indent=0):
    pos = 0
    prefix = '  ' * indent
    while pos < len(data):
        tag, pos = decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        name = f" ({field_names[field_num]})" if field_names and field_num in field_names else ""
        
        if wire_type == 0:  # varint
            value, pos = decode_varint(data, pos)
            print(f'{prefix}field {field_num}{name} (varint): {value}')
        elif wire_type == 1:  # 64-bit
            value = struct.unpack_from('<Q', data, pos)[0]
            pos += 8
            print(f'{prefix}field {field_num}{name} (fixed64): 0x{value:016X}')
        elif wire_type == 2:  # length-delimited
            length, pos = decode_varint(data, pos)
            value = data[pos:pos+length]
            pos += length
            try:
                s = value.decode('utf-8')
                if all(32 <= ord(c) < 127 or ord(c) == 10 for c in s):
                    print(f'{prefix}field {field_num}{name} (str[{length}]): "{s}"')
                    continue
            except:
                pass
            print(f'{prefix}field {field_num}{name} (bytes[{length}]):')
            decode_protobuf(value, indent=indent+1)
        elif wire_type == 5:  # 32-bit
            value = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            print(f'{prefix}field {field_num}{name} (fixed32): 0x{value:08X}')
        else:
            print(f'{prefix}UNKNOWN field {field_num} wire_type={wire_type} at pos {pos}')
            break

print('=== InitialLoginData ===')
decode_protobuf(data, ILD_FIELDS)
