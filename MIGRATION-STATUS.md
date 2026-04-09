# Blizzless-DiiIS — Migration 2.7.4 → 2.8.0: Status & Debug Report

**Last updated**: 2026-04-08  
**Current blocker**: Client stuck on "Retrieving Hero List" — no error code, cancel button appears after timeout.

---

## 1. Project Overview

- **Repository**: `c:\Users\Beroli\projects\blizzless-diiis`
- **Tech stack**: .NET 7 / C#, Docker (PostgreSQL 17 + app), DotNetty 0.7.5
- **Proto library**: Google.ProtocolBuffers C# (compiled DLL at `src/DiIiS-NA/libs/Google.ProtocolBuffers.dll` — CANNOT be modified)
- **Client**: Diablo III64.exe 2.8.0, build 99920
- **Account**: iwannatry@ / iwannatry#4016 (admin, SRP6a hash)
- **TLS cert**: Self-signed, CN=us.actual.battle.net, SAN, password "123", file `bnetserver.p12`
- **Hosts**: `127.0.0.1 us.actual.battle.net` and `eu.actual.battle.net`

### Docker Build/Deploy Commands
```bash
docker builder prune -af
docker build --no-cache -t blizzless-diiis-diiis-na-server .
docker compose up -d
# MUST use --no-cache AND prune to ensure code changes take effect
# Context transfers ~381MB, build takes ~80s
```

### View Logs
```bash
docker logs diiis-na-server 2>&1 | findstr "TRACE"       # Filtered trace
docker logs diiis-na-server 2>&1 | Select-Object -Last 200 # Last 200 lines
```

---

## 2. What Works (Completed Fixes)

| # | Fix | Files Modified | Status |
|---|-----|---------------|--------|
| 1 | Version numbers: build 99920, version 2.8.0 | `VersionInfo.cs` (7 locations) | ✅ |
| 2 | TLS certificate with SAN entries | `bnetserver.p12`, Windows cert store | ✅ |
| 3 | HTTPS REST server (fixed Code 14001) | `RestSession.cs` | ✅ |
| 4 | Service hash 0x5DBB51C2 error responses | `BattleClient.cs` | ✅ |
| 5 | Proto required fields bypass (`hasAccountId` etc.) | Multiple proto files in `DiIiSNet/` | ✅ |
| 6 | **Variant field number mismatch** — server's `bgs.protocol.Variant` had different field numbers than 2.8.0 client | `AttributeTypes.cs` — base64 descriptor + FieldNumber constants | ✅ CRITICAL |
| 7 | Handshake bypass removal (`is280Handshake` block) | `GameUtilitiesService.cs` | ✅ |
| 8 | PresenceService.Update deserialization (EntityId.IsInitialized) | Proto entities | ✅ |
| 9 | CustomMessageId echo in responses | `GameUtilitiesService.cs` | ✅ |
| 10 | `is_response=true` in all response headers | `BattleClient.cs` SendResponse | ✅ |
| 11 | Response `serviceId=254` confirmed correct | `BattleClient.cs` `_responseServiceId` | ✅ (serviceId=0 BREAKS login → status=3010) |
| 12 | InitialLoginData via notification (BUILD_V3 pattern) | `GameUtilitiesService.cs` | ✅ |
| 13 | Case 6 returns `InitialLoginDataQueuedResponse` not full data | `GameUtilitiesService.cs` case 6 | ✅ (latest fix) |
| 14 | `InitialLoginDataResponse.serviceId` always = 1 | `GameUtilitiesService.cs` InitialLoginTask.run() | ✅ (latest fix) |
| 15 | Guild replication deferred via `Task.Run` + 500ms delay | `GameUtilitiesService.cs` InitialLoginTask.run() | ✅ (latest fix) |

### Variant Field Numbers (2.8.0 — PATCHED)
```
IntValue=2, Float=3, String=4, Message=5, Uint=6, Bool=11, Blob=12, Fourcc=13
```
File: `src/DiIiSNet/bgs/protocol/AttributeTypes.cs`

---

## 3. Current Blocker: "Retrieving Hero List" Timeout

### Observed Client Behavior
1. Client connects, authenticates (14+ RPC calls succeed)
2. Client sends msg=6 (InitialLoginDataRequest)
3. Server responds with `InitialLoginDataQueuedResponse{serviceId=1, timeoutTickInterval=2000}`
4. Server sends Notification with `InitialLoginDataResponse` containing full hero/account data
5. Client DOES receive and process it (sends msg=7 GetGameAccountSettings)
6. Client then sends `RequestDisconnect` with errorCode=0 and shows timeout

### Connection Flow (Complete Trace Analysis)
```
Tokens 0-12: Connect, Auth, Subscribe services — ALL OK
Token 13: msg=6 (1st InitialLogin)
  → Server: queued response + notification (serviceId=1)
  → ChannelListener callbacks from GuildManager.ReplicateGuilds() interfere
  → Client does NOT process → 4 KeepAlive pings (~2 min timeout)
Token 22: msg=7 (GetGameAccountSettings) → OK
Token 23: GenerateWebCredentials → OK
Token 24: msg=6 (2nd InitialLogin RETRY)
  → No ChannelListener callbacks (GuildChannelsRevealed=true)
  → Client DOES process → sends msg=7
Token 27: msg=7 response → OK
Token 28: RequestDisconnect errorCode=0
```

**KEY**: Even when the client processes the notification (2nd attempt), it still disconnects after getting the msg=7 response. This suggests a **data content issue** in `InitialLoginData`, not a protocol framing issue.

### Latest Fixes Applied (Not Yet Confirmed Working)
The three latest fixes (items 13-15 above) aim to:
- Return proper `InitialLoginDataQueuedResponse` (was returning full `InitialLoginDataResponse`)
- Always use `serviceId=1` (was conditionally 0)
- Defer guild callbacks to avoid interference

These MIGHT fix the first-attempt failure, but may not fix the post-notification disconnect.

---

## 4. Hypotheses for Next Steps (Prioritized)

### HIGH Priority
1. **Missing `SessionFlags` field in InitialLoginData** — Field 11 (uint32) is NEVER set. 2.8.0 may require it. Try `Init.SetSessionFlags(0U)`.
   - File: `src/DiIiS-NA/BGS-Server/ServicesSystem/Services/GameUtilitiesService.cs`, in `InitialLoginTask.run()` around line 175

2. **Notification message wrapper format may be wrong for 2.8.0** — Currently uses v1 `bgs.protocol.notification.v1.Notification` with `D3.NotificationMessage` type. Client 2.8.0 may expect:
   - Different attribute names
   - Different notification type string
   - v2 notification format (`bgs.protocol.notification.v2.client`) — but v2 uses different Attribute type
   - File: `src/DiIiSNet/bgs/protocol/notification/v2/client/NotificationTypes.cs`

3. **Proto field number mismatches in nested messages** — Variant was patched but other protos (AccountDigest, HeroDigest, GameAccountSettings, etc.) may also have field number differences between server protos and client 2.8.0. Need to verify with Ghidra.
   - Key proto files: `src/DiIiSNet/D3/Account/Account.cs`, `src/DiIiSNet/D3/Notification/Notification.cs`, `src/DiIiSNet/D3/Client/Client.cs`

### MEDIUM Priority
4. **`OnInitialLoginDataRequest` dead code** — The old method at line ~1206 in `GameUtilitiesService.cs` still exists but is no longer called. Can be removed for clarity.

5. **`InitialLoginDataResponse.serviceId` meaning unclear** — What does `serviceId` mean inside `InitialLoginDataResponse`? It might not be the BNet serviceId but a D3-specific service identifier. Verify in Ghidra.

6. **Content of InitialLoginData may be wrong** — Some fields may have wrong format/values:
   - `AchievementsContentHandle.Hash` — is this hash valid for 2.8.0?
   - `SyncedVars` string format — spaces as delimiters seem unusual
   - `ContentLicenses` IDs — may have changed in 2.8.0

### LOW Priority
7. **Game server opcodes** — Completely different opcode table in 2.8.0 (155 vs 553 opcodes). Not blocking hero list but will block gameplay. See `migracaoplano.md` for extracted opcode table.

---

## 5. Key Code Locations

### BNet Protocol Layer
| File | Purpose |
|------|---------|
| `src/DiIiS-NA/BGS-Server/Battle/BattleClient.cs` | Core connection handler, SendResponse (line ~555), SendRequest (line ~478), ChannelRead0 (line ~142) |
| `src/DiIiS-NA/BGS-Server/Base/BNetCodec.cs` | WebSocket packet encoding (line ~37) |
| `src/DiIiS-NA/BGS-Server/ServicesSystem/Services/ConnectionSerivce.cs` | Connect RPC, service hash registration (line ~21) |

### D3 Game Utilities
| File | Purpose |
|------|---------|
| `src/DiIiS-NA/BGS-Server/ServicesSystem/Services/GameUtilitiesService.cs` | ALL D3 game messages. Case 6 = InitialLogin (line ~319), InitialLoginTask class (line ~26), 54 message IDs implemented |

### Proto Definitions
| File | Purpose |
|------|---------|
| `src/DiIiSNet/bgs/protocol/AttributeTypes.cs` | `Variant` field numbers (PATCHED for 2.8.0) |
| `src/DiIiSNet/D3/Notification/Notification.cs` | `InitialLoginData` (18 fields), `InitialLoginDataResponse`, `InitialLoginDataQueuedResponse` |
| `src/DiIiSNet/D3/Account/Account.cs` | `AccountDigest` (15 fields) |
| `src/DiIiSNet/D3/GameMessage/GameMessage.cs` | D3 game message protos |
| `src/DiIiSNet/D3/Client/Client.cs` | `GameAccountSettings` proto |
| `src/DiIiSNet/bgs/protocol/notification/v2/client/NotificationTypes.cs` | v2 Notification (NOT currently used) |

### Config / Infrastructure
| File | Purpose |
|------|---------|
| `Dockerfile` | Multi-stage build, .NET 7 SDK → runtime |
| `docker-compose.yml` | Ports: 83, 1119, 1345, 2001, 9800, 9100, 5432 |
| `src/DiIiS-NA/config.ini` | Server config (BindIP=0.0.0.0, REST.Public=true) |
| `db/initdb/dump.sql` | Database seed |

---

## 5.1 
### Extracted files from Client 2.8 using Ghidra is here:
C:\Users\Beroli\Downloads\D32.8.9-extracted

## 5.2 
### The Client 2.8 to to tests is here:
C:\Users\Beroli\Downloads\Diablo III

## 6. Protocol Details (BNet v2)

### Response Format
- `serviceId=254` + `is_response=true` — CONFIRMED correct. serviceId=0 causes status=3010.
- Header format: `08-FE-01-18-{token}-28-{size}-30-{status}-48-01`
- Header proto: ServiceId(1), MethodId(2), Token(3), ObjectId(4), Size(5), Status(6), Error(7), Timeout(8), IsResponse(9), ForwardTargets(10), ServiceHash(11 fixed32)

### Server→Client Requests
- `serviceId=0` + `serviceHash` (e.g., 0xE1CB2EA8 for NotificationListener)
- Token counter separate from client's token space

### Client Info
- SDK: "BGS C++ SDK" v6.5.1
- `useBindlessRpc=true`, no BindRequest in ConnectRequest
- Service hashes registered: 19 entries (0x54DFDA17→0x01 through 0x26, plus 0x51)

### Service Hash Map
```
0x54DFDA17=0x01  0xD4DCD093=0x02  0x71240E35=0x03  0xBBDA171F=0x04
0xF084FC20=0x05  0xBF8C8094=0x06  0x166FE4A1=0x07  0xB96F5297=0x08
0x6F259A13=0x09  0xE1CB2EA8=0x0A  0xBC872C22=0x0B  0x7FE36B32=0x0C
233634817=0x0D   0x62DA0891=0x0E  510168069=0x0F   0x45E59C4D=0x10
0x135185EF=0x11  1910276758=0x51  2119327385=0x26
```

### InitialLogin Flow (msg=6)
1. Client sends `ProcessClientRequest` with `CustomMessageId=6` and `InitialLoginDataRequest` payload
2. Server responds with `InitialLoginDataQueuedResponse{serviceId=1, timeoutTickInterval=2000}` wrapped in `CustomMessage` attribute
3. Server sends `bgs.protocol.notification.v1.Notification` (hash 0xE1CB2EA8, method 1) containing:
   - Type: `"D3.NotificationMessage"`
   - Attribute[0]: `D3.NotificationMessage.MessageId` = IntValue(1)
   - Attribute[1]: `D3.NotificationMessage.Payload` = MessageValue(InitialLoginDataResponse bytes)
4. `InitialLoginDataResponse` contains: errorCode=0, serviceId=1, loginData=InitialLoginData
5. `InitialLoginData` has 18 possible fields (see proto section above). Server currently sets all except SessionFlags (field 11).

---

## 7. Diagnostic Traces Deployed

The following `Console.Error.WriteLine("[TRACE] ...")` statements are in the codebase:

| Location | Trace | Purpose |
|----------|-------|---------|
| `BattleClient.ChannelRead0` | `RECV: serviceId, serviceHash, methodId, token...` | Every incoming packet |
| `BattleClient.SendResponse` | `SendResponse HEADER: token, status, hdrHex` | Every outgoing response |
| `BattleClient.SendRequest` | `SendRequest NOTIFICATION HEADER/BODY` | Notification payloads |
| `ConnectionSerivce.Connect` | `ConnectRequest` hex dump | Client handshake |
| `GameUtilitiesService` | `ProcessClientRequest: messageId={0}` | Every D3 message |
| `GameUtilitiesService` case 6 | `BUILD_V3: case 6` | InitialLogin trigger |
| `InitialLoginTask.run` | `InitialLoginDataResponse` field-by-field | Notification content |

These traces write to stderr and appear in `docker logs diiis-na-server`.

---

## 8. Files Created During Migration

These files were created during debugging and can be safely removed:
- `migracaoplano.md` — Original migration plan (Portuguese)
- `fulllog.txt`, `fulllog2.txt`, `full_log.txt` — Server log captures
- `ExtractOpcodes.java`, `ExtractOpcodes2.java`, `ExtractOpcodes3.java`, `ExtractOpcodesFinal.java`, `ExtractOpcodeSizes.java`, `FindWireOpcodes.java`, `FindAuthHashes.java` — Ghidra scripts
- `opcodes_280.cs` — Extracted opcode table (if exists)

---

## 9. Things That Were Tested and FAILED

| Test | Result | Revert Status |
|------|--------|---------------|
| `serviceId=0` in responses (instead of 254) | Client returns status=3010, breaks entire login | ✅ Reverted to 254 |
| Returning full `InitialLoginDataResponse` in case 6 RPC response | Client ignores it, waits for notification anyway | ✅ Changed to QueuedResponse |
| Synchronous `GuildManager.ReplicateGuilds()` before notification | ChannelListener callbacks interfere, client ignores 1st notification | ✅ Deferred to Task.Run |
| `InitialLoginDataResponse.serviceId` conditional (0 when GuildChannelsRevealed) | 2nd attempt notification had serviceId=0 | ✅ Changed to always 1 |

---

## 10. Quick-Start for New Session

**Goal**: Fix "Retrieving Hero List" timeout in Diablo III 2.8.0 client connecting to blizzless-diiis server.

**State**: Auth works, notification is sent and received, but client disconnects after processing it.

**Recommended first actions**:
1. Check if the 3 latest fixes (items 13-15) resolved the first-attempt failure by reading the trace:
   ```bash
   docker logs diiis-na-server 2>&1 | findstr "TRACE"
   ```
2. If still failing, try adding `SessionFlags` to `InitialLoginData`:
   - In `InitialLoginTask.run()`, add `Init.SetSessionFlags(0U)` before building
3. Compare `InitialLoginData` proto field numbers with what 2.8.0 client expects (use Ghidra on `Diablo III64.exe`)
4. Consider capturing actual Blizzard server traffic with a proxy to compare notification format
5. Check if `D3.NotificationMessage` attribute names/format changed in 2.8.0

**Key principle**: The Variant field number mismatch was the biggest breakthrough. Other proto messages likely have similar mismatches between the server's generated code and the 2.8.0 wire format. A systematic audit of all proto field numbers against Ghidra analysis would be the most productive approach.
