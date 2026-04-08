# Plano de Migração — Blizzless Server 2.7.4 → 2.8.0

## Versões

| | Atual | Nova |
|---|---|---|
| **Versão** | 2.7.4 | 2.8.0 |
| **Build** | 84161 | 99920 |
| **Internal Build** | 22044 | ? (extrair) |
| **Formato de dados** | MPQ (.mpq) | CASC (.idx) |

---

## TIER 1 — Obrigatório (sem isso, o cliente nem conecta)

| # | O que | Arquivo | Dificuldade | Status |
|---|-------|---------|-------------|--------|
| 1 | **Protocol Hash** — hash do protocolo de rede. Cliente e servidor DEVEM coincidir | `src/DiIiS-NA/Core/Versions/VersionInfo.cs` L132 | ALTA — extrair do exe novo | ⬜ |
| 2 | **Build number** — mudar de `22044`/`84161` para o build do 2.8.0 | `src/DiIiS-NA/Core/Versions/VersionInfo.cs` L17,28,127 | Fácil | ⬜ |
| 3 | **Aurora build string** — string de identificação do client | `src/DiIiS-NA/Core/Versions/VersionInfo.cs` L32 | Extrair do exe | ⬜ |
| 4 | **Auth module hashes** — SHA256 de cada módulo de autenticação, por plataforma | `src/DiIiS-NA/Core/Versions/VersionInfo.cs` L61-86 | ALTA — extrair do exe | ⬜ |
| 5 | **Opcodes** — IDs de mensagens de rede. Se mudaram, o servidor não entende o cliente | `src/DiIiS-NA/D3-GameServer/MessageSystem/Opcodes.cs` | ALTA — extrair/comparar | ⬜ |

### Como extrair os dados do Tier 1

- Usar **HydraPro** ou **IDA/Ghidra** no `Diablo III64.exe` (2.8.0) para obter:
  - Protocol Hash (valor 32-bit no binário)
  - Auth module hashes (SHA256 dos módulos)
  - Aurora build string
  - Tabela de opcodes (mensagens de rede)

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
| `src/DiIiS-NA/Core/MPQ/Dicts.cs` | Dicionário SNO gigante (~40K linhas) |
| `src/DiIiS-NA/D3-GameServer/Core/Types/SNO/ActorSno.cs` | Enum de atores |
| `src/DiIiSNet/D3/GameMessage/GameMessage.cs` | Protobuf das mensagens do jogo |
| `src/DiIiS-NA/D3-GameServer/ClientSystem/ClientManager.cs` L94 | Handshake — ecoa ProtocolHash do cliente |

---

## Inconsistência encontrada no servidor atual

- `VersionInfo.Ingame.MajorVersion` está como `"2.6.9"` mas tudo mais diz `2.7.4` — pode ser intencional (versão interna vs display)

---

## Ferramentas necessárias

- **HydraPro** — para extrair dados do executável (protocol hash, opcodes, auth hashes)
- **CascView / CascLib** — para extrair dados do formato CASC do cliente 2.8.0
- **Ghidra/IDA** (opcional) — para análise mais detalhada do binário se HydraPro não for suficiente

---

## Ordem de execução recomendada

1. Extrair dados do exe 2.8.0 com HydraPro (Tier 1 items)
2. Extrair dados CASC com CascView (SNO dicts, achievements, MPQ data)
3. Atualizar `VersionInfo.cs` (build, protocol hash, auth hashes, Aurora string)
4. Atualizar/adicionar opcodes em `Opcodes.cs`
5. Atualizar SNO dicts (`Dicts.cs`, `ActorSno.cs`)
6. Resolver MPQ → CASC (converter ou adaptar loader)
7. Atualizar protobufs se necessário
8. Atualizar strings de versão (Tier 3)
9. Rebuild e testar conexão
10. Testar gameplay
