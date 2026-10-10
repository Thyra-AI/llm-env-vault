# Estudo: instalar o Thyra Vault em qualquer editor de IA, e deixá-lo pequeno e leve

Data: 2026-10-08. Estado do código: working tree com os diálogos web ainda por commitar.
Este documento é um **estudo e levantamento**; nada aqui foi alterado no código. As decisões que
dependem de si estão na secção 7.

Legenda de confiança: **[verificado]** = confirmado nesta sessão numa fonte ou medido no código;
**[memória]** = conhecimento anterior, não reconfirmado hoje; **[a verificar]** = não confirmado.

---

## 1. Resumo

1. **O que impede a instalação fácil não é o nosso código, é a forma de distribuição.** Hoje o
   projeto só se instala como plugin do Claude Code (git clone). `pyproject.toml` diz de propósito
   que não é um pacote. Sem pacote no PyPI não existe o comando de uma linha
   (`uvx thyra-vault`) que todos os outros editores aceitam.
2. **Há um bloqueio escondido:** o cofre fica em `CLAUDE_PLUGIN_DATA`, ou, se essa variável não
   existir, **ao lado do código** (`vault_lib/store.py:53-55`). Com `uvx`/`pipx` o código vive numa
   cache descartável, e o cofre ia com ela. Antes de publicar é obrigatório dar ao cofre uma
   pasta de dados própria do utilizador.
3. **O maior ganho de peso é trocar o SDK `mcp`** (38 MB instalados → 16 MB, −58%). O servidor
   usa só 3 coisas do SDK: `FastMCP`, `@mcp.tool()` (13 vezes) e `mcp.run()`.
4. **O maior ganho de código é fazer o Tk ser só um renderizador** dos fluxos que já escrevi para a
   web: `gui.py` tem 2 952 linhas que duplicam a lógica de `webui/flows.py` (1 007 linhas).
5. **Ordem recomendada:** primeiro "instalável em todo o lado" (fase 1, pequena e sem risco para
   quem já usa), depois "leve" (fase 2), e só por fim os cortes grandes (fase 3).

---

## 2. Como cada editor instala um servidor MCP

Todos os editores lançam o servidor como um **subprocesso stdio** a partir de um comando. Por isso
a pergunta é só: *qual é o comando de uma linha que funciona em qualquer máquina?* A resposta
universal é `uvx thyra-vault` (precisa do pacote no PyPI e do `uv` instalado).

| Editor | Como se instala | Confiança |
|---|---|---|
| **Claude Code** | Já funciona como plugin: `claude plugin marketplace add Thyra-AI/llm-env-vault` e `claude plugin install llm-env-vault@llm-env-vault`. Sem plugin: `claude mcp add thyra-vault -- uvx thyra-vault` | marketplace/install [verificado]; `claude mcp add` [memória] |
| **Claude Desktop** | Ficheiro `.mcpb` (zip com `manifest.json`), instalação com um clique. `server.type` pode ser `uv`, `python`, `node` ou binário. Criado com `mcpb init` e `mcpb pack` (`npm i -g @anthropic-ai/mcpb`) | [verificado] |
| **Cursor** | Link de um clique: `cursor://anysphere.cursor-deeplink/mcp/install?name=NOME&config=BASE64_DO_JSON`. Ficheiros `~/.cursor/mcp.json` ou `.cursor/mcp.json` | link [verificado, docs do Cursor]; ficheiros [memória] |
| **VS Code (Copilot)** | `code --add-mcp '{"name":"thyra-vault","command":"uvx","args":["thyra-vault"]}'`. Ficheiros: `.vscode/mcp.json` (chave `servers`), ou `.mcp.json` portátil (chave `mcpServers`). MCP é GA desde a 1.102 | [verificado]. O link `vscode:mcp/install?…` existe mas **o formato exato não foi confirmado** [a verificar] |
| **Codex CLI** | `~/.codex/config.toml` com `[mcp_servers.thyra-vault]`, campos `command`, `args`, `env`; também por projeto em `.codex/config.toml` | [verificado] |
| **Gemini CLI** | `~/.gemini/settings.json` (ou `.gemini/settings.json`), objeto `mcpServers` com `command`, `args`, `env`, `cwd` | [verificado] |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` (Windows: `%USERPROFILE%\.codeium\windsurf\`), objeto `mcpServers` | [verificado] |
| **Zed** | `context_servers` nas definições. As fontes lidas eram antigas; o formato atual pode ter mudado | [a verificar] |
| **Cline, Roo, Continue, JetBrains** | Todos usam o mesmo desenho (nome + comando + args + env) | [memória] |

**Registo oficial MCP** (alimenta diretórios e alguns clientes): ficheiro `server.json` na raiz,
nome no formato `io.github.<utilizador>/<servidor>`, pacote no PyPI cuja descrição contém a linha
`mcp-name: io.github.<utilizador>/<servidor>`, publicado com `mcp-publisher` (de preferência no CI
a cada tag). [verificado]

### O que há de comum, e portanto o que construir

Um **único** bloco serve quase todos:

```json
{ "command": "uvx", "args": ["thyra-vault"] }
```

Cada editor só muda o *ficheiro* e o nome da chave (`mcpServers`, `servers`,
`context_servers`, TOML). É isto que um instalador automático tem de gerir.

---

## 3. O que falta hoje no projeto para isto funcionar

| # | Problema | Onde | Gravidade |
|---|---|---|---|
| 1 | Não é um pacote: `pyproject.toml` não tem `[project]`, nem script de consola, e diz isso de propósito | `pyproject.toml` | Bloqueia o `uvx` |
| 2 | **O cofre vai para ao lado do código** quando não há `CLAUDE_PLUGIN_DATA`. Em `uvx`/`pipx` isso é uma cache apagável | `vault_lib/store.py:53-55` (já recusa criar cofre dentro de `plugins/cache`, linhas 1119-1143, mas não oferece alternativa) | **Perda de dados**: crítico |
| 3 | Dois mecanismos de instalação de dependências: `plugin_launcher.py` (452 linhas) cria um venv e instala com pip/uv, o que o `uvx` já faz sozinho | `plugin_launcher.py` | Duplicação |
| 4 | Os comandos `/llm-env-vault:protect` e `:doctor` são do Claude Code. Noutros editores não existem; o equivalente seria regras (`.cursor/rules`, `AGENTS.md`) | `commands/` | Só conforto |
| 5 | "Windows é a plataforma testada". macOS/Linux precisam de `python` no PATH. Com `uvx` o Python vem do `uv`, o que resolve | README, `plugin.json` | Melhora com o `uvx` |
| 6 | Python sem Tk (Homebrew, Linux mínimo, distros) obrigava a ter o `python-tk`. Já resolvido pelo diálogo web | `uibackend.py` | Resolvido |
| 7 | Supply chain: `uvx thyra-vault` corre código do PyPI sem hashes. Hoje só o Windows tem lockfile com hashes | README (notas de segurança) | Tem de ser documentado: fixar versão e publicar com *trusted publishing* |

**Nomes livres no PyPI** (medido hoje, resposta 404 = livre): `thyra-vault`, `thyra-vault-mcp`,
`llm-env-vault`, `thyra_vault`. [verificado]

---

## 4. Proposta de instalação

### Fase 1: "instalável em todo o lado" (pequena)

1. **Pacote no PyPI** `thyra-vault`: `[project]` + `[project.scripts] thyra-vault = "mcp_server:main"`.
   Dependências mínimas: `cryptography` e o SDK `mcp` (até à fase 2).
2. **Pasta de dados própria do utilizador** (corrige o ponto 2). Ordem: `THYRA_VAULT_HOME` >
   `CLAUDE_PLUGIN_DATA` > pasta de dados do sistema (`%APPDATA%\ThyraVault`,
   `~/Library/Application Support/ThyraVault`, `$XDG_DATA_HOME/thyra-vault`). Migração
   única e **sem apagar nada** de um cofre antigo ao lado do código.
3. **`thyra-vault install --client <cursor|vscode|claude-desktop|codex|gemini|windsurf|zed>`**:
   escreve a entrada no ficheiro do editor (com cópia de segurança, `--dry-run`, idempotente) e
   `thyra-vault doctor` para diagnosticar. Estimativa: ~150-250 linhas, só com a biblioteca padrão
   (JSON; para o TOML do Codex basta anexar um bloco de texto).
4. **Botões e one-liners no README**: link do Cursor, `code --add-mcp`, `claude mcp add`, blocos
   para Codex/Gemini/Windsurf/Zed.
5. **`server.json` + `mcp-publisher` no CI** (publicação automática a cada tag).
6. **`.mcpb` para o Claude Desktop** (`server.type: "uv"` aponta para o mesmo pacote).
7. O **plugin do Claude Code mantém-se** como está (continua a ser o caminho mais rico, com
   comandos e a instalação por marketplace).

Resultado: em qualquer editor, "copie uma linha" ou "clique num botão".

### Fase 2: "leve" (ver secção 5)

### Fase 3: cortes grandes, só depois de decidir (ver secção 5)

---

## 5. Levantamento do código: o que pesa e o que se pode cortar

### 5.1 Peso de instalação (medido em venvs novos, Python 3.12)

| Configuração | site-packages |
|---|---|
| Hoje: `mcp[cli]==1.29.0` + `cryptography` | **38 MB** |
| Sem o extra `[cli]` (`mcp` simples) | 31 MB (−7 MB, −18%) |
| **Só `cryptography`** (servidor MCP próprio, sem o SDK) | **16 MB (−22 MB, −58%)** |

Maiores pacotes hoje: `cryptography` 14,7 MB; `pydantic_core` 4,8; `pydantic` 3,1; `rich` 2,1;
`mcp` 1,9; `anyio` 1,4; `rpds` 1,0; `click` 0,9; `jsonschema` 0,7; `httpx` 0,7. O extra `[cli]`
só acrescenta `typer` e `python-dotenv`, e arrasta `rich` e `click`: **não é usado**
(`mcp_server.py` só importa `FastMCP`).

`cryptography` (AES-GCM) é insubstituível pela biblioteca padrão. O scrypt, esse, já é padrão
(`hashlib`).

### 5.2 Código Python (linhas, sem testes)

| Ficheiro | Linhas | Notas |
|---|---|---|
| `vault_lib/store.py` | 4 085 | Núcleo. 23 menções a v1/Fernet (compatibilidade) |
| `vault_lib/gui.py` | 2 952 | Diálogos Tk. **Lógica duplicada** de `webui/flows.py` |
| `mcp_server.py` | 2 383 | 13 ferramentas |
| `vault_lib/crypto.py` | 1 157 | 15 menções a v1/Fernet |
| `vault_lib/webui/flows.py` | 1 007 | Lógica dos mesmos diálogos |
| `vault_lib/singleview.py` | 802 | Funcionalidade "materialize" com leituras limitadas |
| `vault_lib/trust.py` | 580 | Confiança 8 h |
| `vault_lib/webui/server.py` | 562 | Servidor loopback + janela de aplicação |
| `plugin_launcher.py` | 452 | Venv + pip; redundante com `uvx` |
| `vault_lib/procs.py` | 380 | Execução de comandos |
| `vault_lib/legacy_swap.py` | 369 | Recuperação do `swap` removido na 2.0 |
| `vault_lib/uihelpers.py` | 337 | Partilhado |
| resto | ~460 | |
| **Total** | **15 535** | Testes: 16 627 linhas. Docs: 251 KB (README 936 linhas, CHANGELOG 1 124) |

### 5.3 Página web embutida (`vault_lib/web_dist/`)

1,7 MB: JS 1 604 KB + CSS 99 KB. O JS está **sem minificar de propósito** (o validador do
marketplace rejeita o que não consegue inspecionar). Minificado, o mesmo JS pesava 672 KB
(212 KB com gzip), medido num build anterior. A galeria de desenvolvimento **já não vai** para
produção (0 ocorrências no bundle). Os 7 idiomas são 140 KB de JSON, todos carregados mesmo
usando só um.

### 5.4 Opções, com ganho estimado e risco

| # | Opção | Ganho | Risco | Esforço |
|---|---|---|---|---|
| A | Passar `mcp[cli]` para `mcp` | −7 MB instalados | Muito baixo | 1 linha + lockfile |
| B | **Servidor MCP próprio** em biblioteca padrão (initialize, tools/list, tools/call, ping, esquemas JSON a partir das assinaturas) | **−22 MB** (−58%), instalação de segundos | Médio: tem de falar bem o protocolo com cada cliente (versões 2024-11-05 a atuais) | ~300 linhas (estimativa) + testes contra Claude Code, Cursor, VS Code |
| C | Carregar só o idioma ativo na página (um ficheiro por idioma) | −120 KB no bundle | Baixo | pequeno |
| D | Remover componentes shadcn e dependências que o ecrã genérico não usa | −centenas de KB | Baixo | pequeno |
| E | Minificar o bundle | −930 KB | **Pode chumbar no validador**; teria de se confirmar com `claude plugin validate` | trivial |
| F | **Renderizador "lite" sem React** (≈7 tipos de bloco e 3 de campo: ~500 linhas de TS + CSS) | bundle de 1,7 MB para algumas dezenas de KB (estimativa) | Contraria a sua regra "sempre shadcn"; perde-se a animação dos componentes | médio |
| G | **Tk como mero renderizador dos fluxos** (um só sítio com a lógica) | `gui.py` 2 952 → ~500 linhas (estimativa): **−2 400 linhas** e menos divergência entre os dois UIs | Alto: os testes do Tk (`test_gui_v2`, `_tk_checks`, `test_gui_helpers`) dependem dos internos atuais; as garantias de foco e de teclas têm de ser reprovadas | grande |
| H | Remover `legacy_swap.py` e a recuperação associada | −369 linhas | Só numa versão major, com aviso: deixa sem recuperação quem ainda tenha um `.env` "trocado" da 1.x | pequeno |
| I | Remover o suporte ao cofre v1 (Fernet) | ~−40 menções em `store`/`crypto` | Só numa major, com migração prévia obrigatória | médio |
| J | Remover `plugin_launcher.py` | −452 linhas | Só quando o `uvx`/pacote for o caminho principal; o plugin do Claude Code passa a lançar `uvx` | médio |
| K | Aparar README/CHANGELOG (251 KB) | menos ruído | Nenhum | pequeno |

### 5.5 O que **não** recomendo cortar

`store.py`, `crypto.py`, `trust.py`, `procs.py` e `singleview.py` são funcionalidades de segurança
com testes e com histórico de correções. São grandes, mas não são "gordura". Cortar linhas aqui sem
cortar funcionalidade é refactor de risco, não otimização.

---

## 6. Riscos transversais

- **Segurança do diálogo web em editores com browser integrado** (Cursor, Windsurf e outros têm
  ferramentas de browser): o agente pode alcançar a porta local. Mitigado, não eliminado
  (README, "Browser dialogs"). Em máquinas onde o Tk funciona, `auto` mantém a janela nativa.
- **`uvx` sem fixar versão** corre sempre a última publicação. Recomendar `uvx thyra-vault==X.Y.Z`
  nos one-liners e publicar com *trusted publishing* + atestados.
- **Mudar o local do cofre** é a alteração de maior risco de toda a fase 1: o utilizador não pode
  "perder" o cofre por uma atualização. Exige migração testada e nunca destrutiva.
- **Nome**: o produto passou a chamar-se Thyra Vault, mas o identificador do plugin continua
  `llm-env-vault` (mudá-lo parte instalações). O pacote PyPI novo seria `thyra-vault`, o que
  deixa dois nomes técnicos em paralelo; tem de ficar explícito na documentação.

---

## 7. Decisões que dependem de si

1. **Publicar no PyPI como `thyra-vault`?** (nome livre hoje). Condição para tudo o resto da fase 1.
2. **Pasta de dados do cofre:** aprovar a ordem `THYRA_VAULT_HOME` > `CLAUDE_PLUGIN_DATA` > pasta do
   sistema, com migração não destrutiva.
3. **Servidor MCP próprio (opção B)?** É a maior poupança de peso, mas é a que mais testes de
   compatibilidade exige. Alternativa conservadora: só a opção A.
4. **Qual UI manter a longo prazo?** Manter os dois (mais código), ou Tk e web a partilhar os
   fluxos (opção G, grande), ou só o web. Cada escolha muda o modelo de segurança.
5. **Regra "sempre shadcn" vs. página minúscula (opção F).** Pode ficar com o shadcn e reduzir (C, D,
   talvez E), ou aceitar um renderizador leve.
6. **Aceita a minificação (E)?** Só depois de correr `claude plugin validate --strict`.
7. **Versão major (3.0)** para remover `legacy_swap`, cofre v1 e o launcher?

---

## 7b. Executáveis e pacotes de sistema (.exe, .deb, .pkg, ...)

Pergunta: dá para distribuir como instalador nativo, em várias plataformas, sem exigir Python?
**Sim, e foi testado aqui (só Linux x86_64; Windows e macOS não puderam ser testados).**

### O que foi construído e medido (scratchpad, nada no repositório)

| Artefacto | Resultado |
|---|---|
| Executável único `thyra-vault` (PyInstaller 6.22, Python 3.12), **com Tk** | 27,8 MB |
| O mesmo **sem Tk** (só diálogo web) | 26,7 MB |
| Tempo de construção | ~20 s cada |
| Arranque a frio até à primeira resposta MCP | 0,6 s |
| Aperto de mão MCP (`initialize` + `tools/list`) com ambiente vazio (`env -i`), sem Python do sistema | **OK: 13 ferramentas** |
| `.deb` real com `dpkg-deb` (`/usr/bin/thyra-vault`, `control`, copyright) | 26,4 MB, binário extraído do `.deb` também responde ao protocolo |

Não instalei o `.deb` (exigiria `sudo` e mexer no sistema); só o construí, inspecionei e extraí.

### Formatos por plataforma

| Plataforma | Formatos possíveis | Notas |
|---|---|---|
| **Windows** | `thyra-vault.exe`; instalador MSI (WiX) ou Inno Setup; `winget`; Scoop; Chocolatey | Sem assinatura de código o SmartScreen avisa; os `.exe` do PyInstaller são conhecidos por falsos positivos de antivírus (preferir "onedir" dentro de um instalador assinado). Certificado de assinatura é custo recorrente |
| **macOS** | binário por arquitetura (arm64 e x64), `.pkg`/`.dmg`; **Homebrew tap** (`brew install thyra-ai/tap/thyra-vault`) | Notarização exige conta Apple Developer (paga). O Homebrew é o caminho mais simples |
| **Linux** | `.deb` (provado), `.rpm` (com `nfpm`/`fpm`), AppImage, tarball | **Snap e Flatpak não servem**: o confinamento impede lançar comandos arbitrários e ler as pastas dos projetos, que é a função do `run_with_env` |
| **Todos, sem Python** | pacote npm com um binário por plataforma (`npx -y @thyra/vault`), no estilo do esbuild; ou `.mcpb` do Claude Desktop com `server.type: "binary"` | npm [memória]; `.mcpb` com binários pré-compilados [verificado] |

O PyInstaller **não cruza plataformas**: é preciso construir em cada sistema. Num CI (GitHub
Actions) seria uma matriz: `windows-latest`, `macos-14` (arm64), `macos-13` (x64),
`ubuntu-22.04` (x64) e `ubuntu-22.04-arm`.

### Limites encontrados (honestos)

1. **Piso do glibc no Linux = 2.34**, medido pela etiqueta da roda do `cryptography` 50.0.2
   (`manylinux_2_34`). Funciona em Ubuntu 22.04+, Debian 12+, RHEL 9+; **não** em Ubuntu 20.04,
   Debian 11 ou RHEL 8, nem em Alpine (musl). Fixar uma versão mais antiga do `cryptography`
   (`manylinux_2_28`) baixaria o piso para o RHEL 8. Construí no Ubuntu 26.04: não basta construir
   num sistema velho se a dependência já exige o novo.
2. **O cofre vai para uma pasta temporária.** Num executável de ficheiro único, `__file__` aponta
   para uma pasta de extração apagada à saída, e `store.py:53-55` usa o código como localização
   de recurso. Os meus testes definiram `CLAUDE_PLUGIN_DATA`; sem isso o cofre seria perdido.
   *(Inferido do código, não demonstrado.)* É o **mesmo bloqueio** do `uvx` (secção 3, ponto 2),
   por isso a pasta de dados própria do utilizador tem de existir antes de qualquer destes
   formatos.
3. **O binário é opaco.** O validador do marketplace rejeita o que não consegue inspecionar, e é
   uma ferramenta de segredos: quem a instala quer poder verificar o que corre. Executáveis só são
   defensáveis com **assinatura, somas de verificação, atestados de proveniência (SLSA) e SBOM**,
   publicados a partir de um CI público, e **fora do repositório do plugin** (GitHub Releases).
4. **Tamanho:** ~27 MB por plataforma é o dobro do Python puro (16 MB com a opção B da secção 5.4).
   Trocar o SDK `mcp` por um servidor próprio reduziria também o executável (estimativa, não medida).
5. **Pequeno defeito encontrado:** o servidor anuncia-se como versão `1.29.0` (a do SDK `mcp`) e não
   como `2.2.1`. Convém passar a versão do produto ao `FastMCP`.

### Recomendação

1. **Primeiro o pacote PyPI + `uvx`/`pipx`** (inspecionável, leve, uma linha em todos os
   editores). É o caminho principal.
2. **Depois, como comodidade para quem não tem Python nem `uv`:** uma *release* no GitHub com um
   binário por plataforma, `.deb`/`.rpm`, instalador do Windows assinado, Homebrew tap e `winget`,
   tudo gerado por um CI com atestados. Nunca dentro do repositório do plugin.
3. O npm e o `.mcpb` com binário só se houver procura.

Decisão adicional: **8. Quer binários nativos?** Se sim, convém decidir antes se aceita o custo
recorrente de assinatura de código (Windows e macOS) e a manutenção da matriz de CI.

---

## 8. Fontes

- Cursor, links de instalação MCP: <https://cursor.com/docs/mcp/install-links> [verificado]
- VS Code, servidores MCP (`--add-mcp`, ficheiros `mcp.json`): <https://code.visualstudio.com/docs/copilot/customization/mcp-servers> [verificado]
- MCP Bundles (`.mcpb`): <https://github.com/modelcontextprotocol/mcpb> [verificado]
- Registo oficial MCP e `mcp-publisher`: <https://modelcontextprotocol.info/tools/registry/publishing/> [verificado]
- Codex CLI, MCP: <https://developers.openai.com/codex/mcp> [verificado]
- Gemini CLI, MCP: <https://geminicli.com/docs/tools/mcp-server/> [verificado]
- Medições: `du`/`wc` e venvs novos com `uv`, nesta máquina, 2026-10-08.
