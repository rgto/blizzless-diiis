# Plano de Migração — Blizzless Server 2.7.4 → 2.8.0

## Versões

| | Atual | Nova |
|---|---|---|
| **Versão** | 2.7.4 | 2.8.0 |
| **Build** | 84161 | 99920 |
| **Internal Build** | 22044 | 99920 |
| **Build String** | `2.7.4.84161` | `2.8.0.99920 (136444-1774217)` |
| **Branch** | — | `branches/2_8_0` |
| **Formato de dados** | MPQ (.mpq) | CASC (.idx) |

---

## TIER 1 — Obrigatório (sem isso, o cliente nem conecta)

| # | O que | Arquivo | Dificuldade | Status |
|---|-------|---------|-------------|--------|
| 1 | **Protocol Hash** — hash do protocolo de rede. **O servidor NÃO valida** — apenas ecoa o que o cliente envia. Não bloqueia conexão. | `src/DiIiS-NA/Core/Versions/VersionInfo.cs` L132 | BAIXA — não precisa extrair | ✅ Investigado |
| 2 | **Build number** — mudar de `22044`/`84161` para `99920` | `src/DiIiS-NA/Core/Versions/VersionInfo.cs` L17,28,127 | Fácil | ⬜ |
| 3 | **Aurora build string** — NÃO armazenada como literal no exe 2.8.0. Construída em runtime. A validação está **comentada** no servidor (`AuthenticationService.cs` L80-86). | `src/DiIiS-NA/Core/Versions/VersionInfo.cs` L32 | BAIXA — capturar do client ao conectar ou inventar | ✅ Investigado |
| 4 | **Auth module hashes** — **O servidor NÃO valida** os hashes. São dead code. Hashes mudaram de 2.7.4→2.8.0 (nenhum dos 6 hashes atuais existe no exe novo). | `src/DiIiS-NA/Core/Versions/VersionInfo.cs` L61-86 | BAIXA — opcionalmente atualizar, mas não bloqueia | ✅ Investigado |
| 5 | **Opcodes** — Protocolo 2.8.0 reestruturado: **155 opcodes** (vs ~553 em 2.7.4). Tipos genéricos (SimpleMessage, ANNDataMessage…) deixaram de ter aliases múltiplos. **Requer reestruturação do message dispatch.** Tabela completa extraída em `opcodes_280.cs`. | `src/DiIiS-NA/D3-GameServer/MessageSystem/Opcodes.cs` + `GameMessage.cs` + todos os `[Message()]` attributes | **MUITO ALTA** — reestruturação arquitetural | ✅ Extraído |

### Resultados da Extração (Ghidra + strings)

#### Build Info
- **Build string**: `2.8.0.99920 (136444-1774217)`
- **Branch**: `branches/2_8_0`
- **Build format**: `%s: %s (build %d)` / `Build: %d`

#### Protocol Hash
- O ProtocolHash é lido em runtime de uma estrutura global (`[0x1416f64d8]+0x24`)
- Computado por uma função que **lê a hash do registry de mensagens** (não hardcoded)
- **CRÍTICO**: O servidor em `ClientManager.cs` L94 ecoa `message.ProtocolHash` e `message.SNOPackHash` **sem validar** — aceita qualquer valor
- **Ação**: Apenas atualizar o valor em `VersionInfo.cs` para referência. O protocolo continuará funcionando.

#### Aurora Build String
- `"Aurora HASH_public"` **NÃO encontrada** no exe 2.8.0 (encontrada apenas `"Aurora has rejected the token"`)
- A string é construída em runtime no Bnet Agent, não no exe do jogo
- **Ação**: Capturar com sniffer ao correr o cliente 2.8.0, ou simplesmente aceitar qualquer string (validação desligada)

#### Auth Module Hashes
- Todos os 6 hashes atuais (Password, SSO, Thumbprint, Token, RiskFingerprint, Agreement) **NÃO existem** no exe 2.8.0
- Os hashes são usados pelo ResourceService para instruir o cliente sobre qual módulo carregar
- O servidor **nunca valida** o hash que o cliente retorna
- **Ação**: Para funcionar, o servidor precisa enviar hashes válidos que o cliente 2.8.0 reconheça. Extrair do DLL modules ou usar fileless approach.

#### Opcodes — DESCOBERTA CRÍTICA

**O protocolo 2.8.0 foi radicalmente reestruturado:**

| | 2.7.4 | 2.8.0 |
|---|---|---|
| **Total de wire opcodes** | ~553 | **155** |
| **Bits no wire** | 10 | 10 (confirmado: bounds check `CMP EDX,0x9B`) |
| **SimpleMessage** | ~70 aliases (opcodes 12,19,29…) | **1 opcode (51)** |
| **GenericBlobMessage** | ~35 aliases | **1 opcode (52)** |
| **ANNDataMessage** | ~35 aliases | **1 opcode (71)** |
| **DWordDataMessage** | ~14 aliases | **1 opcode (58)** |
| **VersionsMessage** | opcode 20, SIZE 48 | opcode 20, SIZE 48 ✓ |
| **QuitGameMessage** | opcode 3 | opcode 75 |

**Tabela completa**: `opcodes_280.cs` (155 entries, 140 com sizes confirmados)

**Método de extração**:
- Type table encontrada em `0x1414051F8` (155 ponteiros × 8 bytes)
- Calibrada com VersionsMessage no index 20
- Sizes extraídos das accessor functions em `0x1408A6xxx-0x1408A8xxx`
- 101 sizes de inline accessors + 39 de JMP epilogue (SIZE 16 default) + 15 sub-structures

Mensagens **novas** em 2.8.0:
- `WarningCountdownNotificationMessage` (37), `BlizzconCVarsMessage` (152)
- `PRTransformMessage` (148), `RitualTetherEffectMessage` (127)
- `SetDungeonMessage` (0), `SetDungeonDialogMessage` (40), `SetDungeonResultsMessage` (44)
- `EnterKnownLookOverrides` (78), `BlizzconEndScreenMessage` (38)

Nota: `UberBosssClosingMessage` (3 's') — typo original da Blizzard.

**Impacto no servidor — REESTRUTURAÇÃO NECESSÁRIA:**

Em 2.7.4, o servidor usa `[Message(Opcodes.LoadingWarping)]` para mapear o opcode 12 → `SimpleMessage`. Existem ~70 opcodes diferentes que mapeiam para `SimpleMessage`, cada um representando um evento diferente (LoadingWarping, LeaveConsoleGame, DeathAck, Ping, etc.).

Em 2.8.0, `SimpleMessage` é **um único opcode (51)**. Não há como distinguir LoadingWarping de DeathAck pelo opcode — o cliente 2.8.0 usa um mecanismo diferente (provavelmente um campo dentro da mensagem ou um sistema de sub-comandos).

**Arquivos afetados por esta mudança:**
- `Opcodes.cs` — substituir enum completo
- `GameMessage.cs` — alterar `ParseMessage()` e factory
- Todos os ficheiros com `[Message(Opcodes.XXX)]` — remapear
- `GameClient.cs` L76 — hardcoded opcode overrides (96, 369, 269) inválidos
- Todas as classes `SimpleMessage`, `ANNDataMessage`, `GenericBlobMessage`, etc. — consolidar registos

---

## TIER 2 — Obrigatório (sem isso, bugs graves de gameplay)

| # | O que | Arquivo | Dificuldade | Status |
|---|-------|---------|-------------|--------|
| 6 | **SNO Dictionaries** — mapeamento nome↔ID de todos os objetos do jogo (~40K linhas) | `src/DiIiS-NA/Core/MPQ/Dicts.cs` | ALTA — gerar do novo cliente | ⬜ |
| 7 | **ActorSno enum** — enum de todos os atores | `src/DiIiS-NA/D3-GameServer/Core/Types/SNO/ActorSno.cs` | ALTA | ⬜ |
| 8 | **MPQ → CASC** — cliente 2.8.0 usa CASC em vez de MPQ. Precisa converter ou adaptar o loader | `src/DiIiS-NA/Core/MPQ/` + `Blizzless.csproj` L104-116 | MUITO ALTA | ⬜ |
| 9 | **Protobuf definitions** — se mensagens mudaram de formato | `src/DiIiSNet/D3/` (vários) | ALTA | ⬜ |
| 10 | **Achievement file** (.achu) + hash | `src/DiIiS-NA/D3-GameServer/AchievementSystem/AchievementManager.cs` | MÉDIA | ⬜ |

### Sobre MPQ → CASC

O cliente 2.8.0 **não usa mais arquivos .mpq**. O formato agora é CASC (`.idx` + data files). Opções:
1. **Converter CASC → MPQ** com CascView/CascLib e manter o loader atual
2. **Adaptar o server** para ler CASC diretamente (mudança grande no `MPQStorage`)

---

## TIER 3 — Cosmético (sem isso funciona, mas exibe versão errada)

| # | O que | Arquivo | Status |
|---|-------|---------|--------|
| 11 | String `"2.7.4.84161"` → `"2.8.0.99920"` | `src/DiIiS-NA/Program.cs` L91 | ⬜ |
| 12 | String `"2.7.4.84161"` → `"2.8.0.99920"` | `src/DiIiS-NA/BGS-Server/AccountsSystem/GameAccount.cs` L88 | ⬜ |
| 13 | String em VersionsMessage | `src/DiIiS-NA/D3-GameServer/MessageSystem/Message/Definitions/Game/VersionsMessage.cs` L20 | ⬜ |
| 14 | String `"2.7.4"` → `"2.8.0"` | `src/DiIiS-NA/BGS-Server/GamesSystem/GameDescriptor.cs` L23 | ⬜ |
| 15 | String no REST | `src/DiIiS-NA/REST/RestSession.cs` L92 | ⬜ |

---

## Arquivos-chave para referência

| Arquivo | Função |
|---------|--------|
| `src/DiIiS-NA/Core/Versions/VersionInfo.cs` | Hub central de versão — builds, hashes, protocol |
| `src/DiIiS-NA/D3-GameServer/MessageSystem/Opcodes.cs` | Todos os opcodes de rede (já tem 2.7.1 e 2.7.4, adicionar 2.8.0) |
| `opcodes_280.cs` | Tabela completa de 155 opcodes 2.8.0 extraída do binário |
| `src/DiIiS-NA/Core/MPQ/Dicts.cs` | Dicionário SNO gigante (~40K linhas) |
| `src/DiIiS-NA/D3-GameServer/Core/Types/SNO/ActorSno.cs` | Enum de atores |
| `src/DiIiSNet/D3/GameMessage/GameMessage.cs` | Protobuf das mensagens do jogo |
| `src/DiIiS-NA/D3-GameServer/ClientSystem/ClientManager.cs` L94 | Handshake — ecoa ProtocolHash do cliente |

---

## Inconsistência encontrada no servidor atual

- `VersionInfo.Ingame.MajorVersion` está como `"2.6.9"` mas tudo mais diz `2.7.4` — pode ser intencional (versão interna vs display)

---

## Ferramentas utilizadas

- **Ghidra 12.0.4** — análise do `Diablo III64.exe` 2.8.0 (projeto em `C:\Users\Beroli\Downloads\D32.8.9-extracted\D3289.rep`)
- **strings** (binutils) — extração de strings ASCII (74,839 strings em `strings_output.txt`)
- **CascView / CascLib** — (pendente) para extrair dados do formato CASC do cliente 2.8.0
- **Docker + PostgreSQL** — para testes (containers já configurados)

---

## Ordem de execução recomendada (atualizada)

### Fase 1 — Versão e autenticação (complexidade BAIXA)
1. ✅ Extrair dados do exe 2.8.0 com Ghidra (build info, protocol hash, auth hashes)
2. ✅ Extrair tabela completa de opcodes (155 opcodes → `opcodes_280.cs`)
3. Atualizar `VersionInfo.cs`: build numbers (`22044`→`99920`, `84161`→`99920`)
4. Adicionar Aurora string para 2.8.0 no `ClientVersionMaps` (capturar do client)
5. (Opcional) Atualizar auth module hashes — não bloqueiam se mantidos

### Fase 2 — Reestruturação do protocolo (complexidade MUITO ALTA) ⚠️ NOVO
6. Analisar como 2.8.0 diferencia sub-tipos (e.g., qual campo substitui os aliases SimpleMessage1..70)
7. Substituir enum `Opcodes` por versão 2.8.0 (155 entries)
8. Reestruturar `[Message()]` attributes em todas as classes de mensagem
9. Adaptar `GameMessage.ParseMessage()` e `GameBitBuffer.EncodeMessage()`
10. Corrigir hardcoded opcodes em `GameClient.cs` (L76: opcodes 96, 369, 269)
11. Testar handshake e message round-trip

### Fase 3 — Dados de jogo (complexidade ALTA)
12. Extrair dados CASC com CascView (SNO dicts, achievements)
13. Atualizar SNO dicts (`Dicts.cs`, `ActorSno.cs`)
14. Resolver MPQ → CASC (converter dados ou adaptar loader)
15. Atualizar protobufs se mensagens mudaram de formato

### Fase 4 — Cosmético (complexidade BAIXA)
16. Atualizar strings de versão em todos os arquivos
17. Rebuild e testar conexão
18. Testar gameplay

## Avaliação de complexidade (atualizada)

**Boa notícia**: Extração de dados do binário está **completa** — temos build info, opcodes, sizes.

**Más notícias**: A reestruturação do protocolo é **muito mais profunda** do que esperado:
- Protocol Hash → servidor ecoa, não valida (**eliminado** ✅)
- Auth hashes → dead code, não validados (**reduzido** ✅)
- Aurora string → validação comentada (**reduzido** ✅)
- Opcodes → **reestruturação arquitetural** (155 vs ~553, aliases eliminados) ⚠️

**Bloqueadores por ordem de impacto:**
1. **Reestruturação de opcodes** (Fase 2) — afeta ~50+ ficheiros com `[Message()]` attributes, lógica de dispatch, e possivelmente a serialização de mensagens genéricas
2. **MPQ → CASC** (Fase 3) — mudança no formato de dados do cliente
3. **SNO dicts** (Fase 3) — volume grande mas mecânico
