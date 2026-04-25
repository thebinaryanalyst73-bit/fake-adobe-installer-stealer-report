# Relatório de Análise Forense: O Malware Oculto Dentro de um Instalador Falso da Adobe

> **Como um pacote pirata da Adobe distribuído via Telegram entrega um infostealer totalmente operacional
> que evade todos os 72 principais motores de antivírus — uma investigação técnica completa**
>
> *Pesquisa de Cibersegurança Defensiva — 14 de abril de 2026*

---

> [!CAUTION]
> **Importante aviso legal:** Este relatório foi produzido exclusivamente para fins de segurança defensiva — conscientização sobre ameaças, engenharia de detecção e orientação de resposta a incidentes para usuários e equipes de segurança. Todos os detalhes técnicos são fornecidos para ajudar pessoas a detectar e remediar esta ameaça específica. Este artigo não contém código de exploração, ferramentas ofensivas, instruções de roubo de credenciais nem qualquer conteúdo que permita uso malicioso. A metodologia e o escopo da análise seguem os mesmos padrões usados por grandes empresas de inteligência de ameaças, incluindo Mandiant, CrowdStrike, Kaspersky GReAT e Palo Alto Networks Unit 42, todas as quais publicam relatórios semelhantes regularmente.

> [!NOTE]
> **Uma observação sobre a qualidade da evidência:** Ao longo deste relatório, as descobertas são explicitamente marcadas como **confirmadas** (verificáveis de forma independente a partir de fontes públicas), **observadas** (documentadas em logs comportamentais de sandbox) ou **inferidas** (conclusões baseadas em evidências disponíveis). Essa distinção é intencional. O objetivo é precisão, não sensacionalismo.

---

## Índice

1. [Resumo do Arquivo](#1-resumo-do-arquivo)
2. [Contexto e Origem](#2-contexto-e-origem)
3. [Análise Estática do Binário](#3-análise-estática-do-binário)
4. [A Arquitetura em 4 Camadas — Engenharia Reversa Completa](#4-a-arquitetura-em-4-camadas--engenharia-reversa-completa)
5. [A Cadeia de Ataque — O que Acontece Momento a Momento](#5-a-cadeia-de-ataque--o-que-acontece-momento-a-momento)
6. [Análise Dinâmica — Dados Comportamentais de Sandbox](#6-análise-dinâmica--dados-comportamentais-de-sandbox)
7. [Infraestrutura de Comando e Controle](#7-infraestrutura-de-comando-e-controle)
8. [Inteligência de Ameaças](#8-inteligência-de-ameaças)
9. [Indicadores de Comprometimento](#9-indicadores-de-comprometimento)
10. [Resposta a Incidentes](#10-resposta-a-incidentes)
11. [Conclusão](#11-conclusão)
12. [Referências e Índice de Fontes](#12-referências-e-índice-de-fontes)

---

## Por que este relatório existe

No início de abril de 2026, um pesquisador que atende pelo apelido `rocket1337` publicou uma análise detalhada de engenharia reversa no VirusTotal identificando um infostealer ativo incorporado em um arquivo que alegava ser um instalador do Adobe Illustrator 2026. O malware circulava desde pelo menos janeiro de 2026, foi catalogado no banco de dados de malware MWDB por um pesquisador diferente em fevereiro de 2025 e acumulou um histórico de submissões ao VirusTotal ao longo de mais de um ano — tudo isso enquanto mantinha zero detecções entre 72 principais motores de antivírus.

O objetivo deste relatório é consolidar tudo o que se sabe sobre essa ameaça em um único documento de referência completo para usuários que possam ter baixado e executado o arquivo, e para profissionais de segurança que precisem de IOCs abrangentes e dados comportamentais para engenharia de detecção.

---

## 1. Resumo do Arquivo

O principal objeto desta análise:

| Campo                        | Valor                                                              |
| ---------------------------- | ------------------------------------------------------------------ |
| **Nome do arquivo**          | `Set-up.exe` (nome interno: `sourcepart.dat`)                      |
| **SHA256**                   | `3d20655679c8829a6baad001851905927ef1b826e3eea594b7be3f8331211e39` |
| **MD5**                      | `e9d48daf4748eee45abf308b85e88b71`                                 |
| **Tamanho do arquivo**       | 7,28 MB (7.638.016 bytes)                                          |
| **Tipo de arquivo**          | Win32 EXE — PE32 (32-bit)                                          |
| **Compilador**               | Visual Studio 2019 v16.2.3 (build 27905)                           |
| **Timestamp PE (wrapper)**   | `2020-10-02 04:16:30 UTC` *(veja a observação abaixo)*             |
| **DLL do payload compilada** | 3 de janeiro de 2026 *(confirmado a partir dos metadados .NET)*    |
| **Assinatura digital**       | Ausente — afirma copyright da Adobe, mas não está assinado         |
| **Primeira submissão ao VT** | 20 de fevereiro de 2025                                            |
| **Detecções AV estáticas**   | **0 / 72**                                                         |
| **Detecção em sandbox**      | `MALWARE` (Yomi Hunter)                                            |
| **Status do servidor C2**    | **Ativo** em 9 de abril de 2026 *(testado ao vivo)*                |
| **Framework de malware**     | infostealer .NET 4.7.2, entrega via WiX SfxCA                      |

> [!NOTE]
> **Observação sobre o timestamp PE de 2020:** O wrapper externo `Set-up.exe` carrega um timestamp de compilação de 2 de outubro de 2020, enquanto o payload .NET incorporado foi compilado em 3 de janeiro de 2026. Timestamps PE no binário externo podem ser facilmente forjados ou representar um framework WiX reaproveitado. O timestamp dos metadados da assembly .NET do payload em 3 de janeiro de 2026 é significativamente mais difícil de falsificar e é corroborado pela primeira submissão ao VirusTotal em 5 de janeiro de 2026 — dois dias após a compilação.

---

## 2. Contexto e Origem

### 2.1 Canal de Distribuição

O arquivo chegou dentro de um pacote torrent apresentado como Adobe Illustrator 2026 (v30.3) Multilingual, atribuído ao conhecido distribuidor pirata m0nkrus e postado no tracker uztracker.net. O torrent continha um único arquivo ISO — `Adobe.Illustrator.2026.u3.Multilingual.iso` (3,43 GB, MD5: `8e8d18572326bd1e948c1d8b17ec49f7`) — que, ao ser montado, expunha três arquivos ao usuário.

### 2.2 Arquivos no Pacote

| Arquivo          | Tamanho     | Veredito                    | Observações                                                                                           |
| ---------------- | ----------- | --------------------------- | ----------------------------------------------------------------------------------------------------- |
| `AutoPlay.exe`   | 185 KB      | ✅ **Legítimo confirmado**   | Launcher genuíno do Adobe CS6 AutoPlay de 2008; visto mais de 100.000 vezes como limpo pela Kaspersky |
| **`Set-up.exe`** | **7,28 MB** | 🔴 **Malicioso confirmado** | **O infostealer — assunto de todo este relatório**                                                    |
| `autorun.inf`    | 70 B        | ✅ **Inerte confirmado**     | Texto simples; AutoRun desativado desde o Windows 7; um flag genérico da Trellix ENS                  |

### 2.3 Confirmação entre Campanhas

> [!IMPORTANT]
> **Confirmado:** O pesquisador `rocket1337` documentou em sua análise de 9 de abril de 2026 no VirusTotal (visível publicamente na aba Community de `487aca2b...71cd`) que o hash da DLL payload idêntica, o endpoint C2 e a sequência da cadeia de ataque foram observados em um pacote separado descrito como um crack do Adobe Photoshop 2026 trojanizado. A DLL `MSICustomActionDLL.dll` (`487aca2b...71cd`) é compartilhada entre ambas as campanhas. Isso é verificável de forma independente: a página da DLL no VirusTotal mostra dois pais de execução distintos — um MSI associado ao Illustrator e um MSI associado ao Photoshop — ambos submetidos no mesmo intervalo de tempo.

A DLL do payload foi compilada em **3 de janeiro de 2026** e enviada pela primeira vez ao VirusTotal em **5 de janeiro de 2026**, aproximadamente três meses antes da aparição deste torrent de abril de 2026. A infraestrutura de ataque foi construída e testada bem antes do início da distribuição.

### 2.4 O que Sabemos Sobre o Ator da Ameaça

O método de distribuição, a infraestrutura pré-construída, a engenharia profissional de evasão e a segmentação multi-produto sugerem uma operação organizada em vez de um indivíduo oportunista. Além disso, nenhuma atribuição é reivindicada e não deve ser inferida. Vários matches de regras YARA contra padrões de APT28 e Turla foram disparados pelo THOR APT Scanner, mas estes quase certamente refletem padrões de código compartilhados de bibliotecas comuns do framework .NET, e não atribuição direta — uma limitação bem documentada da atribuição baseada em YARA em binários .NET, reconhecida pela Nextron Systems em suas próprias notas publicadas sobre matches do VirusTotal.

---

## 3. Análise Estática do Binário

### 3.1 Estrutura e Propriedades PE

| Propriedade                       | Valor                                                                         |
| --------------------------------- | ----------------------------------------------------------------------------- |
| **Arquitetura**                   | Win32 EXE PE32 — 32-bit, executa em x64 via WoW64                             |
| **Timestamp de compilação**       | `2020-10-02 04:16:30 UTC` *(wrapper externo; veja a observação na §1)*        |
| **Seções PE**                     | `.text` `.rdata` `.data` `.rsrc` `.reloc`                                     |
| **Entropia (seção .reloc)**       | 6,66 — conteúdo incorporado elevado e ofuscado                                |
| **Imphash**                       | `337783faf868eb54d41c823f63ce0359`                                            |
| **Assinatura digital**            | **AUSENTE**                                                                   |
| **String de copyright declarada** | `© 2020-2025 Adobe. All rights reserved.` **(FALSA — sem assinatura válida)** |

### 3.2 O que a Tabela de Imports Revela

Antes de qualquer código ser executado, as funções da Windows API importadas pelo binário revelam o conjunto completo de capacidades pretendidas. Os grupos a seguir foram identificados a partir da análise estática do PE — um método objetivo e reproduzível por qualquer analista com uma ferramenta de análise PE examinando o mesmo hash.

**Roubo de credenciais via DPAPI:** `CryptProtectData` e `CryptUnprotectData` são usados para descriptografar credenciais armazenadas pelo Chrome, Edge e Firefox — esses navegadores usam a Data Protection API do Windows para criptografar senhas salvas. `CredReadW`, `CredEnumerateW` e `CredWriteW` fornecem acesso total ao cofre do Windows Credential Manager. `BCryptEncrypt` e `BCryptDecrypt` lidam com a recriptografia dos dados roubados antes da exfiltração.

**Anti-análise e evasão:** `IsDebuggerPresent` detecta depuradores anexados e altera a execução de acordo. `GetTickCount` permite detecção baseada em timing de sandbox — sandboxes frequentemente rodam mais rápido do que hardware real, e medições de tempo podem expor isso. A detecção de artefatos de VM cobre VMware, VirtualBox, Parallels, QEMU, Xen, AWS e GCP.

**Enumeração e reconhecimento do sistema:** `CreateToolhelp32Snapshot`, `Process32FirstW` e `Process32NextW` enumeram todos os processos em execução. `GetUserNameW` e `GetComputerNameExW` coletam identidade do usuário e hostname. `WinVerifyTrust` e `WTHelperGetProvSignerFromChain` verificam assinaturas digitais de processos em execução para selecionar alvos de injeção.

**Persistência e escalonamento de privilégios:** `DuplicateTokenEx` e `ImpersonateLoggedOnUser` permitem roubo e impersonação de token. `AdjustTokenPrivileges` e `LookupPrivilegeValueW` tratam do escalonamento de privilégios. `CreateNamedPipeW` e `ConnectNamedPipe` estabelecem canais covert de comunicação entre processos característicos de loaders e ferramentas de acesso remoto.

### 3.3 Recursos Incorporados

A seção `.rsrc` contém 18 imagens PNG (gráficos da interface do instalador), 21 arquivos de dicionário (strings da interface multilíngue), 6 arquivos JavaScript, 4 arquivos CSS, 4 arquivos SVG e 2 arquivos HTML. Esses recursos existem para fazer o instalador parecer genuinamente legítimo durante uma inspeção visual casual.

---

## 4. A Arquitetura em 4 Camadas — Engenharia Reversa Completa

O malware usa uma arquitetura de entrega aninhada onde o payload ativo está enterrado quatro camadas abaixo. O pesquisador `rocket1337` recuperou o código-fonte completo em C# usando ILSpy e publicou a análise completa na aba Community da página VirusTotal da DLL payload (`487aca2b...71cd`) em 9 de abril de 2026. Essa análise está publicamente visível e é verificável de forma independente. O que segue integra essa análise publicada com os dados comportamentais independentes de sandbox produzidos por Zenbox, CAPE Sandbox e VirusTotal Jujubox.

### 4.1 Visão Geral da Arquitetura

```text
Layer 0 — Set-up.exe
          Delivery wrapper presented as Adobe installer
          Extracts and launches the MSI below
                │
                ▼
Layer 1 — Installer.msi
          Cover identity: "Dolby Vision PQ Config Installer"
          Signed with STOLEN, EXPIRED Dolby Laboratories certificate
          Custom action "SummonRah" fires at UI sequence 801
          (this is BEFORE the user sees any installer screen)
                │
                ▼
Layer 2 — SfxCA DLL (WiX Self-Extracting Custom Action)
          Extraction container for the payload
          79,576-byte overlay at entropy 7.9965/8.0 (near-maximum)
          Payload is compressed/encrypted — invisible to AV PE scanning
                │
                ▼
Layer 3 — CAB Archive (embedded in the DLL overlay)
          Microsoft Cabinet format, LZX compression
                │
                ▼
Layer 4 — MSICustomActionDLL.dll
          THE ACTIVE INFOSTEALER PAYLOAD
          16 KB, .NET 4.7.2, compiled January 3, 2026
          C# source recovered and published by rocket1337 via ILSpy
          Executed via: rundll32.exe [...],zzzzInvokeManagedCustomActionOutOfProc
```

### 4.2 Camada 1 — Installer.msi em Detalhe

| Campo         | Valor                                                              |
| ------------- | ------------------------------------------------------------------ |
| **SHA256**    | `45415f110b7961eea726dd3b1c07ebed2bbc44d13e8d92d0d8bd1304ba145d73` |
| **MD5**       | `595eb28f84979f035375a35efe92c259`                                 |
| **Tamanho**   | 1,32 MB                                                            |
| **Compilado** | 4 de março de 2025                                                 |

O MSI se apresenta como o "Dolby Vision PQ Config Installer" da "Dolby", construído usando o legítimo WiX Toolset 5.0.2.0. Ele está assinado com um certificado da Dolby Laboratories emitido pela DigiCert.

> **Confirmado:** O certificado expirou em 22 de outubro de 2025 e contém um flag `HashMismatch` — verificável na seção Signature Info da aba Details do VirusTotal para este hash de arquivo. O conteúdo assinado não corresponde ao conteúdo real do arquivo. Este é um certificado roubado e abusado. Sua presença faz com que muitas ferramentas automatizadas tratem o instalador como confiável sem análise comportamental aprofundada.

A história de disfarce é elaborada: o MSI instala dezenas de arquivos reais de perfil de cor Dolby Vision (`.dv`) em `C:\Windows\System32\spool\drivers\color\` — dados genuínos de calibração de hardware para fabricantes de displays incluindo AUO, BOE, LEN, CMN, CSO e TMA. **Observado:** Os nomes de arquivo específicos foram documentados na análise de arquivos descartados da sandbox. Sua presença faz com que os logs de instalação pareçam totalmente normais.

Antes de executar a ação custom maliciosa, o MSI abre o Windows Vault (`VaultSvc`) e o Clipboard Service (`clipsvc`) — visando credenciais armazenadas. O DNS client (`dnsCache`) também é acessado, consistente com preparação para enumeração de rede.

**Confirmado pela análise do dataset WMI da sandbox:**

```text
IWbemServices::Connect
IWbemServices::CreateInstanceEnum → Win32_ComputerSystemProduct (Hardware UUID)
IWbemServices::ExecQuery → SELECT * FROM Win32_ComputerSystem
IWbemServices::ExecQuery → SELECT * FROM Win32_VideoController (GPU model)
```

**Cadeia de execução observada capturada na sandbox Zenbox:**

```text
msiexec.exe /i "Wixinstaller1.6.msi"
  └─ MsiExec.exe -Embedding [token]
      └─ MsiExec.exe -Embedding [token] C  (WoW64 transition)
          └─ rundll32.exe "MSIB20D.tmp",
               zzzzInvokeManagedCustomActionOutOfProc SfxCA_6478875 1
               MSICustomActionDLL!MSICustomActionDLL.CustomActions.EntryPointOne
```

Quatro regras Sigma dispararam em severidade MEDIUM (todas publicamente disponíveis no repositório SigmaHQ):

| Regra                                          | Autor                                       |
| ---------------------------------------------- | ------------------------------------------- |
| Rundll32 Internet Connection                   | Florian Roth (Nextron Systems)              |
| Unsigned DLL Loaded by Windows Utility         | Swachchhanda Shrawan Poudel                 |
| Amsi.DLL Loaded Via LOLBIN Process             | Nasreddine Bencherchali (Nextron Systems)   |
| Rundll32 Execution With Uncommon DLL Extension | Tim Shelton, Florian Roth, Yassine Oukessou |

### 4.3 Camada 2 — SfxCA DLL em Detalhe

| Campo         | Valor                                                              |
| ------------- | ------------------------------------------------------------------ |
| **SHA256**    | `06875058d4f40be9fb9d065bb4dbc29f67e80339ea261143d123d582c1481171` |
| **MD5**       | `efaa71c29a914094691c2582c657dc1f`                                 |
| **Tamanho**   | 254,71 KB                                                          |
| **Compilado** | 17 de setembro de 2019                                             |

O mecanismo Self-Extracting Custom Action do WiX é uma maneira legítima de entregar código .NET dentro de pacotes MSI. Os autores do malware reaproveitaram todo esse framework confiável como veículo de entrega — emprestando legitimidade de ferramentas reais.

**Confirmado pela análise do PE:** A DLL possui um overlay de 79.576 bytes anexado após o conteúdo padrão do PE com uma entropia de **7,9965 em um máximo teórico de 8,0** — documentado na seção de overlay de PE da aba Details do VirusTotal. Entropia máxima indica compressão ou criptografia máximas. A varredura padrão de seções PE por antivírus não encontra nada suspeito porque o payload não existe nas seções PE; ele existe apenas no overlay, que muitos motores ignoram ou examinam com menos rigor.

**Observado:** A URL de C2 `https://i-odsports.com/aycha/saver.php` apareceu como string de padrão de memória durante a execução na sandbox — documentada na seção Memory Pattern URLs da aba Behavior.

O CAPA confirmou os seguintes comportamentos: detecção de strings anti-VM visando Parallels, QEMU, VMware e VirtualBox; detecção de depurador via breakpoints de memória; anti-debugging baseado em guard pages; criação, envio e tratamento de respostas HTTP; criação e conexão de named pipes; codificação de dados em Base64; acesso a dados WMI via .NET; obtenção de username e hostname.

Uma regra Sigma disparou em severidade **HIGH**: **Suspicious DotNET CLR Usage Log Artifact**
— detecta execução de assembly .NET via um processo LOLBIN. Quando uma assembly .NET roda dentro do `rundll32.exe` pela primeira vez em uma sessão de usuário, o CLR cria um arquivo de log chamado `rundll32.exe.log`. Esse artefato é um indicador forense confiável exatamente desse padrão de ataque.

### 4.4 Camada 4 — MSICustomActionDLL.dll em Detalhe (O Payload Ativo)

| Campo         | Valor                                                              |
| ------------- | ------------------------------------------------------------------ |
| **SHA256**    | `487aca2bbd630c8013ee1992dabb970058c9a737c2fffce0c0a45801408771cd` |
| **MD5**       | `732de0a3ddfeb4b5ad29387d3cbf66ee`                                 |
| **Tamanho**   | 16 KB (16.384 bytes)                                               |
| **Compilado** | 3 de janeiro de 2026                                               |

Esta assembly .NET de 16 kilobytes é o núcleo do infostealer. Os seguintes metadados da assembly .NET são **confirmados** — verificáveis na aba Details da página do arquivo no VirusTotal:

* **Versão CLR:** `v4.0.30319`
* **Module Version ID:** `a38b459e-6347-4e1e-900a-52153b4a58d5`
* **Dependências externas:** `Microsoft.Deployment.WindowsInstaller v3.0.0.0`, `System.Management v4.0.0.0`, `System.Windows.Forms v4.0.0.0`, `System.Core v4.0.0.0`

As definições de tipos .NET são **confirmadas** a partir da listagem da assembly na aba Details do VirusTotal e mapeiam diretamente para capacidades específicas:

| Tipo .NET                                               | Propósito                                           |
| ------------------------------------------------------- | --------------------------------------------------- |
| `System.Management.ManagementObjectSearcher`            | Consultas WMI — Hardware UUID                       |
| `System.Net.HttpWebRequest`                             | HTTP POST para endpoint C2                          |
| `System.Windows.Forms.MessageBox`                       | Falso erro de memória em VMs                        |
| `System.Security.Cryptography.RNGCryptoServiceProvider` | RNG criptográfico                                   |
| `System.Convert` (Base64)                               | Codificação dos dados roubados antes da transmissão |
| `System.Diagnostics.Stopwatch`                          | Detecção baseada em tempo de sandbox                |
| `System.Security.Principal.WindowsIdentity`             | Identidade do usuário atual                         |
| `System.Security.Claims.ClaimsIdentity`                 | Acesso baseado em claims de identidade              |
| `System.Environment.SpecialFolder`                      | Enumeração de pastas especiais                      |

**Ofuscação ROT13 — confirmada e matematicamente verificável:**

As strings de consulta WMI são codificadas com ROT13 para contornar detecção baseada em assinaturas de strings:

```text
Encoded:  Jva32_PbzchgreFlffgrzCebqhpg
Decoded:  Win32_ComputerSystemProduct    ← WMI class queried for Hardware UUID

Encoded:  HHVQ
Decoded:  UUID                           ← property name extracted
```

Verificável com qualquer decodificador ROT13 (por exemplo, `https://rot13.com/`). Essas strings ofuscadas foram documentadas na análise publicada por rocket1337 no VirusTotal e são reproduzíveis de forma independente.

**Presença de PDB indicando desenvolvimento ativo** *(fato confirmado; inferência sobre o significado):*
O arquivo de símbolos de debug `MSICustomActionDLL.pdb` foi deixado dentro do arquivo CAB — confirmado na seção Dropped Files da aba Behavior. Sua presença na lista de arquivos descartados é um fato objetivo. A inferência — de que isso indica desenvolvimento ativo e monitoramento contínuo das taxas de detecção — é razoável, mas continua sendo uma interpretação, não um fato comprovado.

---

## 5. A Cadeia de Ataque — O que Acontece Momento a Momento

Cada etapa é marcada com sua base de evidência.

| Etapa | Ação                                                                        | Base de Evidência                            | Visibilidade para o Usuário                  |
| ----- | --------------------------------------------------------------------------- | -------------------------------------------- | -------------------------------------------- |
| **1** | A ação custom `SummonRah` executa na sequência de UI 801                    | Confirmado — cadeia de execução da sandbox   | Apenas "Preparando a instalação..."          |
| **2** | WMI coleta Hardware UUID, GPU, username, hostname                           | Confirmado — dataset WMI da sandbox          | Nenhuma                                      |
| **3** | POST HTTPS ao C2 com `Flow=PS6` / `Action=Login`                            | Confirmado — teste C2 ao vivo por rocket1337 | Nenhuma                                      |
| **4** | Verificação de VM/sandbox: VMware, VBox, Parallels, QEMU, Xen, AWS, GCP     | Confirmado — CAPA + evasão em sandbox        | **Falso erro se VM detectada → saída limpa** |
| **5** | Renomeia `sourcepart.dat` → `Set-Up.exe`; inicia o instalador real da Adobe | Confirmado — sistema de arquivos da sandbox  | Instalação normal da Adobe                   |
| **6** | `winget install -h --id 9N411ZGN6M6G` *(identidade do app desconhecida)*    | Observado — lista de processos da sandbox    | Nenhuma                                      |
| **7** | `Planora /INSTALL` *(capacidades desconhecidas)*                            | Observado — lista de processos da sandbox    | Nenhuma                                      |
| **8** | Exclui `%TEMP%\MSIB20D.tmp-\` e todo o conteúdo                             | Confirmado — sistema de arquivos da sandbox  | Nenhuma                                      |

**Mensagem de erro falsa exibida em ambientes VM:**

> *"The system does not have enough available memory to run this application effectively.
> Please ensure that you have sufficient free RAM or close unnecessary programs to continue.
> If the issue persists, [...]"*

> [!WARNING]
> **Nota crítica:** As etapas 2 e 3 — coleta e exfiltração de dados — ocorrem **antes**
> da etapa 4. Se você executou este arquivo em uma VM e viu o erro de memória, alguns dados podem já ter sido transmitidos ao servidor C2 antes de o erro aparecer.

> [!NOTE]
> **Caveats importantes sobre as etapas 6 e 7:** O aplicativo da Windows Store correspondente ao ID de pacote do winget `9N411ZGN6M6G` não foi identificado publicamente no momento desta análise. As capacidades, origem e método de persistência do componente `Planora` também são desconhecidos. Ambos estão documentados aqui porque foram observados em execução — não porque seu comportamento seja compreendido.

---

## 6. Análise Dinâmica — Dados Comportamentais de Sandbox

### 6.1 Resultados em Sete Sandboxes

| Sandbox                | Veredito                         | Observações Principais                                                         |
| ---------------------- | -------------------------------- | ------------------------------------------------------------------------------ |
| **Yomi Hunter**        | 🔴 `MALWARE`                     | Única sandbox com classificação positiva de malware                            |
| CAPE Sandbox           | ⚠️ 3 alertas                     | Detecções comportamentais, sem classificação definitiva                        |
| Zenbox                 | ⚠️ 5 alertas / 57 comportamentos | Tags: `calls-wmi`, `checks-usb-bus`, `detect-debug-environment`, `long-sleeps` |
| Microsoft Sysinternals | ⚠️ 99+ comportamentos            | Volume máximo de eventos observado                                             |
| VirusTotal Jujubox     | ⚠️ 50 alertas                    | Múltiplos comportamentos suspeitos                                             |
| C2AE                   | ✅ Sem alertas                    | Evasão bem-sucedida                                                            |
| VirusTotal Observer    | ✅ Sem alertas                    | Evasão bem-sucedida                                                            |

A alta taxa de evasão entre sandboxes é intencional e esperada. A tag `long-sleeps` indica que o malware usa chamadas de sleep prolongadas projetadas para ultrapassar a maioria das janelas de timeout automatizadas de sandbox. A tag `detect-debug-environment` confirma que verificações anti-análise foram observadas disparando.

### 6.2 Injeção de Processo — T1055

**Confirmado pela árvore de processos da sandbox:**

```text
C:\Program Files\Google1084_461961379\bin\updater.exe --update --system ...
C:\Program Files\Google1556_2660802\bin\updater.exe --update --system ...
C:\Program Files\Google2116_724760920\bin\updater.exe --update --system ...
[87+ additional instances following the same pattern]
```

O payload malicioso é injetado em cada instância em execução. Após a injeção, o processo é encerrado. Toda a atividade maliciosa é executada dentro de um binário legítimo assinado pela Google.

**Confirmado a partir de arquivos descartados e diretórios instalados na sandbox:**

```text
C:\Program Files (x86)\Google\GoogleUpdater\136.0.7079.0\
C:\Program Files (x86)\Google\GoogleUpdater\137.0.7115.0\
C:\Program Files (x86)\Google\GoogleUpdater\137.0.7129.0\
C:\Program Files (x86)\Google\GoogleUpdater\138.0.7156.0\
C:\Program Files (x86)\Google\GoogleUpdater\138.0.7194.0\
C:\Program Files (x86)\Google\GoogleUpdater\140.0.7272.0\
C:\Program Files (x86)\Google\GoogleUpdater\140.0.7273.0\
C:\Program Files (x86)\Google\GoogleUpdater\141.0.7340.0\
C:\Program Files (x86)\Google\GoogleUpdater\141.0.7376.0\
```

Cada instalação inclui uma estrutura completa de diretório de relatórios de crash Crashpad. O resultado é indistinguível de uma instalação legítima do Google Updater numa inspeção casual de `C:\Program Files (x86)\Google\`.

### 6.3 Execução por Binário do Sistema — T1218

**Confirmado a partir dos logs de criação de processo da sandbox:**

```text
rundll32.exe "C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp",
  zzzzInvokeManagedCustomActionOutOfProc SfxCA_6478875 1
  MSICustomActionDLL!MSICustomActionDLL.CustomActions.EntryPointOne
```

Do ponto de vista das ferramentas de segurança de endpoint, isso parece um binário assinado do Windows carregando uma DLL de um diretório temporário durante a instalação de software — uma atividade que ocorre legitimamente em milhares de tipos de instaladores.

### 6.4 Persistência — T1543 e T1547

**Confirmado pela análise de registro e serviços na sandbox:** O malware registra serviços `GoogleUpdaterInternalService*` com `Start=2 (SERVICE_AUTO_START)`, significando que eles iniciam automaticamente a cada boot do sistema. Esses serviços executam como LocalSystem, o nível de privilégio mais alto disponível no Windows.

**Confirmado pelas ações no sistema de arquivos da sandbox:** Uma chave DPAPI é gravada em `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\941a2910-ceaf-4083-a069-04b1d985b6d1`. Gravar uma chave DPAPI no nível LocalSystem concede ao malware capacidade persistente de descriptografar segredos criptografados no nível do sistema.

### 6.5 Acesso a Credenciais — T1056 e T1179

**Observado a partir das tags comportamentais da sandbox e da análise CAPA:** Keylogging (T1056) e hooking (T1179) são documentados como capacidades confirmadas a partir da análise CAPA da DLL SfxCA e do payload. A implementação específica — polling para keylogging, locais específicos de hooking — é descrita na análise publicada por rocket1337 com base no código-fonte C# recuperado. As tags comportamentais da sandbox confirmam as categorias de capacidade; o mecanismo específico é documentado a partir da análise do código-fonte.

### 6.6 Reconhecimento de Rede

**Confirmado pelos logs de tráfego de rede da sandbox:** Pacotes NetBIOS UDP (porta 137) foram observados sendo enviados para endereços no intervalo `192.168.0.x` durante toda a execução na sandbox — documentado na seção IP Traffic da aba Behavior. Isso mapeia todos os dispositivos do segmento de rede local.

**Confirmado pelos dados comportamentais da sandbox:** O serviço Windows Security Center (`wscsvc`) foi acessado — documentado na seção Services Opened da aba Behavior.

### 6.7 Payloads de Segunda Etapa

**Observado na árvore de processos da sandbox — hashes apenas da sandbox, não verificados separadamente no VirusTotal:**

```text
Set-up.exe (PID 736)
  └─ 5614ba3c7415e4ee3cb1bdbff08cc643.exe  (PID 3032)
  └─ cde09bcdf5fde1e2eac52c0f93362b79.exe  (PID 1416)
```

> [!NOTE]
> Esses hashes dos executáveis filhos vêm da documentação da árvore de processos da sandbox. Eles não foram submetidos separadamente ao VirusTotal como amostras independentes com suas próprias páginas de análise no momento deste relatório. Suas capacidades são desconhecidas além do fato de que foram iniciados e executados.

Onze arquivos foram descartados no total durante a execução completa.

### 6.8 Anti-Forense

**Confirmado pelas ações no sistema de arquivos da sandbox:**

```text
C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp
C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp-\CustomAction.config
C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp-\MSICustomActionDLL.dll
C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp-\MSICustomActionDLL.pdb
C:\Users\[USER]\AppData\Local\Temp\MSIB20D.tmp-\Microsoft.Deployment.WindowsInstaller.dll
```

---

## 7. Infraestrutura de Comando e Controle

### 7.1 O Servidor C2 Ativo

**Confirmado — teste ao vivo documentado na análise de 9 de abril de 2026 de rocket1337 no VirusTotal:**

| Campo                          | Valor                                                              |
| ------------------------------ | ------------------------------------------------------------------ |
| **Endpoint**                   | `POST https://i-odsports.com/aycha/saver.php`                      |
| **IP Primário**                | `104.21.5.5` (Cloudflare CDN)                                      |
| **IP Secundário**              | `172.67.132.177` (Cloudflare CDN)                                  |
| **Resposta confirmada**        | `{"status":"success","message":"Log received and stored."}`        |
| **Camuflagem via GET**         | Requisições GET redirecionam para `avast.com`                      |
| **TLS**                        | v1, serial do certificado `00ac661f8828b2b2220e5ed8e1d6e2913f`     |
| **JA3**                        | `cbcd1d81f242de31fd683d5acbc70dca`                                 |
| **JA3S**                       | `d202ce1ad7e4f3d5b39fb831970e4b49f8cb7426ea09faef21c6ff723a632f2d` |
| **JA4**                        | `t10d120500_d94e65cdb899_559829c2a830`                             |
| **Emissor do certificado TLS** | Google Trust Services (CN=WE1)                                     |

O roteamento por meio da CDN da Cloudflare oculta o IP real do servidor hospedeiro, tornando a derrubada da infraestrutura significativamente mais complexa do que apenas bloquear endereços IP diretos.

### 7.2 Inteligência de Domínio — Um Lookalike Deliberado

O domínio C2 `i-odsports.com` **não** é `odsports.com`. Esses são domínios registrados completamente separados. O legítimo `odsports.com` é uma plataforma chinesa de apostas esportivas (OD体育) registrada desde 2014, sem conexão com esta campanha de malware.

**Todos os campos abaixo são confirmados por consulta pública WHOIS/RDAP em lookup.icann.org e pelas abas de detalhes de domínio do VirusTotal para ambos os domínios:**

| Campo                 | `i-odsports.com` (C2)         | `odsports.com` (Legítimo)           |
| --------------------- | ----------------------------- | ----------------------------------- |
| **Registrado**        | **6 de fevereiro de 2025**    | 7 de março de 2014                  |
| **Registrador**       | Gname.com Pte. Ltd.           | GoDaddy.com                         |
| **Finalidade**        | **Servidor C2 de malware**    | Plataforma esportiva chinesa (OD体育) |
| **Privacidade WHOIS** | Proteção total de privacidade | Registro padrão                     |
| **Nameservers**       | Cloudflare (host anonimizado) | Afternic                            |
| **Detecções VT**      | 0/94                          | 1/94 (categoria Forcepoint)         |

O prefixo `i-` faz `i-odsports.com` parecer um subdomínio ou variante interna da marca esportiva estabelecida quando aparece em alertas SIEM ou logs de rede ao lado de tráfego web legítimo. O domínio foi registrado **nove meses antes da aparição deste torrent**, confirmando construção de infraestrutura pré-planejada.

### 7.3 O que Foi Exfiltrado

**Confirmado a partir do dataset WMI da sandbox e do tráfego de rede combinado com a análise de código-fonte de rocket1337:**

| Dado                       | Método de Coleta                  | Ofuscação                   |
| -------------------------- | --------------------------------- | --------------------------- |
| Hardware UUID              | WMI `Win32_ComputerSystemProduct` | ROT13 na string de consulta |
| Modelo da GPU              | WMI `Win32_VideoController`       | ROT13 na string de consulta |
| Nome de usuário do Windows | WMI e `GetUserNameW`              | Nenhuma                     |
| Hostname do computador     | `GetComputerNameExW`              | Nenhuma                     |
| Versão da campanha         | Hardcoded                         | `Flow=PS6`                  |
| Tipo de evento             | Hardcoded                         | `Action=Login`              |

### 7.4 Infraestrutura de Staging de Payload Secundário

**Observado — apenas strings de padrão de memória:**

```text
trondevuserpackages.s3.amazonaws.com
tronstageuserpackages.s3.amazonaws.com
```

> [!NOTE]
> Esses hostnames foram encontrados na análise de padrões de memória, mas o contato ativo confirmado com esses buckets S3 não foi documentado nos logs de tráfego de rede da sandbox para a amostra analisada. Eles são mencionados aqui como infraestrutura potencial de staging, mas seu uso ativo durante esta execução específica não foi confirmado de forma independente.

---

## 8. Inteligência de Ameaças

### 8.1 Classificação da Família de Malware

**MWDB (cert.pl) — 28 de fevereiro de 2025** *(confirmado, verificável publicamente pelo link MWDB em Referências):*
O pesquisador `petik` catalogou este arquivo com o nome original
`2025-02-28_e9d48daf4748eee45abf308b85e88b71_avoslocker_luca-stealer`, identificando-o como uma combinação de Luca Stealer (alvo de navegadores, carteiras de criptomoedas, cookies de sessão, clientes FTP) e AvosLocker (loader de ransomware).

**THOR APT Scanner (Nextron Systems) — 11 de novembro de 2025** *(confirmado, nomes das regras e datas documentados na aba Community do VirusTotal):*
Cinco regras YARA dispararam a partir do feed comercial VALHALLA, incluindo `MAL_Raccoon_Stealer_V2_Jul22_1` (Raccoon Stealer V2), `APT_RU_MAL_Turla_Jan21_1` e `APT_MAL_macOS_APT28_XAgent_May21_1`. As correspondências Turla e APT28 quase certamente refletem padrões de código compartilhados de bibliotecas comuns do framework .NET, e não atribuição direta ao agente de ameaça — uma limitação documentada e explicitamente reconhecida pela Nextron Systems em suas orientações publicadas sobre interpretação de matches YARA em binários .NET.

**Engenharia reversa (rocket1337) — 9 de abril de 2026** *(análise publicada confirmada, visível independentemente no VT):*
Código-fonte completo em C# recuperado via ILSpy. Infostealer .NET 4.7.2 feito sob medida, não uma ferramenta commodity reaproveitada. A análise publicada está disponível na aba Community da página do arquivo MSICustomActionDLL.dll no VirusTotal e pode ser lida por qualquer usuário registrado.

### 8.2 Mapeamento MITRE ATT&CK

*Todas as atribuições de técnica são baseadas em observações confirmadas de sandbox ou em achados confirmados de análise estática. Cada entrada inclui apenas técnicas para as quais existe evidência.*

| ID    | Tática                 | Técnica                              | Base de Evidência                                               |
| ----- | ---------------------- | ------------------------------------ | --------------------------------------------------------------- |
| T1059 | Execução               | Command & Scripting Interpreter      | Execução de script durante a instalação *(sandbox)*             |
| T1047 | Execução               | Windows Management Instrumentation   | WMI confirmado no dataset da sandbox                            |
| T1218 | Execução / Evasão      | System Binary Proxy — `rundll32`     | Árvore de processos confirmada na sandbox                       |
| T1055 | Execução / Evasão      | Process Injection (×2 sub-técnicas)  | 90+ instâncias do Updater na sandbox                            |
| T1543 | Persistência           | Create / Modify System Process       | Serviços confirmados na sandbox                                 |
| T1547 | Persistência           | Boot/Logon Autostart Execution       | `Start=2` confirmado na sandbox                                 |
| T1179 | Escalada de Privilégio | Hooking                              | Análise CAPA + análise do código-fonte                          |
| T1036 | Evasão de Defesa       | Masquerading                         | Disfarce Dolby confirmado na estrutura MSI                      |
| T1027 | Evasão de Defesa       | Obfuscated Files or Information (×3) | ROT13 confirmado; 4 camadas confirmadas; certificado confirmado |
| T1497 | Evasão de Defesa       | Virtualization/Sandbox Evasion       | CAPA + 5/7 sandboxes mostraram evasão                           |
| T1562 | Evasão de Defesa       | Impair Defenses                      | acesso a `wscsvc` confirmado na sandbox                         |
| T1485 | Impacto                | Data Destruction                     | arquivos excluídos confirmados na sandbox                       |
| T1056 | Coleta                 | Input Capture — Keylogging           | CAPA + tag T1056 confirmada na sandbox                          |
| T1033 | Descoberta             | System Owner/User Discovery          | username via WMI confirmado na sandbox                          |
| T1082 | Descoberta             | System Information Discovery         | UUID, GPU confirmados no WMI da sandbox                         |
| T1083 | Descoberta             | File and Directory Discovery         | operações de sistema de arquivos confirmadas na sandbox         |
| T1087 | Descoberta             | Account Discovery                    | `System.Security.Principal` nos tipos .NET                      |
| T1063 | Descoberta             | Security Software Discovery          | acesso a `wscsvc` confirmado na sandbox                         |
| T1120 | Descoberta             | Peripheral Device Discovery          | tag `checks-usb-bus` confirmada na sandbox                      |
| T1046 | Descoberta             | Network Service Discovery            | NetBIOS UDP 137 confirmado na sandbox                           |
| T1071 | C&C                    | Application Layer Protocol           | HTTP POST confirmado *(teste C2 ao vivo)*                       |
| T1573 | C&C                    | Encrypted Channel                    | TLS confirmado nos logs de rede da sandbox                      |
| T1091 | Movimento Lateral      | Replication via Removable Media      | enumeração USB — apenas preparação, *inferida*                  |

### 8.3 Os Sete Motivos pelos Quais Zero Motores de Antivírus Detectaram

**1. Aninhamento de payload em quatro camadas** *(Confirmado pela análise PE e sandbox)*
A DLL infostealer .NET é extraída apenas na memória em tempo de execução. Motores de antivírus que analisam as seções PE de qualquer arquivo individual não encontram código malicioso — porque o payload não reside em nenhuma seção PE. Ele existe apenas em um overlay criptografado de 79.576 bytes.

**2. Certificado expirado roubado** *(Confirmado pelos detalhes de assinatura do VirusTotal)*
O certificado da Dolby Laboratories faz com que muitas ferramentas tratem o MSI como um instalador confiável sem análise comportamental profunda. O flag `HashMismatch` exige um nível específico de validação de assinatura que muitas ferramentas ignoram.

**3. Ofuscação de strings via ROT13** *(Confirmado — matematicamente verificável)*
Cada string suspeita que as regras YARA dos antivírus corresponderiam está codificada usando ROT13. As formas codificadas não correspondem a assinaturas existentes. Qualquer analista pode verificar os valores decodificados com uma calculadora ROT13.

**4. Anti-depurador e anti-VM** *(Confirmado pelos resultados da sandbox)*
Cinco dos sete ambientes de sandbox não viram nenhum comportamento de malware — prova objetiva de que os mecanismos anti-análise funcionam como projetado.

**5. Living off the land** *(Confirmado pela árvore de processos da sandbox)*
Toda a execução maliciosa acontece dentro de `rundll32.exe` — um binário do Windows assinado pela Microsoft em que as ferramentas de segurança são explicitamente configuradas para confiar.

**6. Atrasos longos de sleep** *(Confirmado pela tag comportamental da Zenbox)*
A tag `long-sleeps` documenta que chamadas de sleep prolongadas foram observadas. Uma sessão automatizada de análise que termina após 60 segundos nunca vê um payload que dorme por mais tempo.

**7. Tráfego C2 camuflado** *(Confirmado pelo teste ao vivo de rocket1337)*
Requisições GET ao domínio C2 redirecionam para `avast.com` — documentado na análise publicada no VirusTotal. Os logs de rede parecem conter tráfego de atualização de antivírus em vez de exfiltração de dados.

---

## 9. Indicadores de Comprometimento

As equipes de segurança devem usar o seguinte para detecção, bloqueio e hunting.

### 9.1 Hashes de Arquivo — Cadeia Completa de Componentes

| Componente                                  | Função            | SHA256                                                             | MD5                                |
| ------------------------------------------- | ----------------- | ------------------------------------------------------------------ | ---------------------------------- |
| `Set-up.exe` / `sourcepart.dat`             | Entrega           | `3d20655679c8829a6baad001851905927ef1b826e3eea594b7be3f8331211e39` | `e9d48daf4748eee45abf308b85e88b71` |
| `Installer.msi`                             | Camada 1          | `45415f110b7961eea726dd3b1c07ebed2bbc44d13e8d92d0d8bd1304ba145d73` | `595eb28f84979f035375a35efe92c259` |
| `SfxCA DLL`                                 | Camada 2          | `06875058d4f40be9fb9d065bb4dbc29f67e80339ea261143d123d582c1481171` | `efaa71c29a914094691c2582c657dc1f` |
| `MSICustomActionDLL.dll`                    | **Payload ativo** | `487aca2bbd630c8013ee1992dabb970058c9a737c2fffce0c0a45801408771cd` | `732de0a3ddfeb4b5ad29387d3cbf66ee` |
| `CustomAction.config`                       | Configuração      | `5d6fd5049f33ac6b16ec0431787fa61c66630ba1916bb4c70f3f6b5844b74ecb` | —                                  |
| `Microsoft.Deployment.WindowsInstaller.dll` | Dependência WiX   | `cf06d4ed4a8baf88c82d6c9ae0efc81c469de6da8788ab35f373b350a4b4cdca` | —                                  |

### 9.2 Indicadores de Rede — Bloqueie Estes

```text
Domain:   i-odsports.com
IP:       104.21.5.5
IP:       172.67.132.177
Endpoint: POST /aycha/saver.php  (on above domain)
JA3:      cbcd1d81f242de31fd683d5acbc70dca
JA3S:     d202ce1ad7e4f3d5b39fb831970e4b49f8cb7426ea09faef21c6ff723a632f2d
Monitor:  trondevuserpackages.s3.amazonaws.com
Monitor:  tronstageuserpackages.s3.amazonaws.com
```

### 9.3 Linha de Comando de Processo Suspeita (Regra de Detecção de Alta Confiança)

```text
rundll32.exe *\AppData\Local\Temp\MSI*.tmp,
zzzzInvokeManagedCustomActionOutOfProc*
MSICustomActionDLL*CustomActions*EntryPointOne
```

Esse padrão de linha de comando é altamente específico para o mecanismo de execução deste malware e é improvável que apareça em software legítimo.

### 9.4 Artefatos de Persistência a Remover

**Serviços** (todos com `Start=2 AUTO_START`):

```text
GoogleUpdaterInternalService136.0.7079.0
GoogleUpdaterInternalService137.0.7115.0
GoogleUpdaterInternalService137.0.7129.0
GoogleUpdaterInternalService138.0.7156.0
GoogleUpdaterInternalService138.0.7194.0
GoogleUpdaterInternalService140.0.7272.0
GoogleUpdaterInternalService140.0.7273.0
GoogleUpdaterInternalService141.0.7340.0
GoogleUpdaterInternalService141.0.7376.0
```

**Diretórios:**

```text
C:\Program Files\Google{process_id}_{random_integer}\
C:\Program Files (x86)\Google\GoogleUpdater\136.*\
C:\Program Files (x86)\Google\GoogleUpdater\137.*\
C:\Program Files (x86)\Google\GoogleUpdater\138.*\
C:\Program Files (x86)\Google\GoogleUpdater\140.*\
C:\Program Files (x86)\Google\GoogleUpdater\141.*\
```

**Arquivos** (história de cobertura — remova se não houver hardware Dolby genuíno presente):

```text
C:\Windows\System32\spool\drivers\color\PQConfig_*.dv
C:\Windows\System32\spool\drivers\color\PQCOnfig_*.dv
```

### 9.5 Indicadores de Registro

```text
HKCU\SOFTWARE\Microsoft\Internet Explorer\Main\
FeatureControl\FEATURE_BROWSER_EMULATION\Set-up.exe = 11001

C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\
941a2910-ceaf-4083-a069-04b1d985b6d1  [DPAPI key written by malware]
```

### 9.6 Mutexes

```text
HDInstaller.log
\Sessions\1\BaseNamedObjects\HDInstaller.log
```

### 9.7 Identificadores da Campanha

```text
HTTP POST parameter: Flow=PS6
HTTP POST parameter: Action=Login
```

---

## 10. Resposta a Incidentes

### 10.1 Avalie Sua Exposição Primeiro

| Cenário                                                | Risco           | Ação                                                                                    |
| ------------------------------------------------------ | --------------- | --------------------------------------------------------------------------------------- |
| `Set-up.exe` executado, Adobe instalado normalmente    | 🔴 **Crítico**  | Assuma comprometimento total — trate todas as credenciais como conhecidas pelo atacante |
| `Set-up.exe` executado, erro falso de memória apareceu | 🟡 **Moderado** | Comprometimento parcial possível — a exfiltração ocorre antes da checagem de VM         |
| ISO montado, mas `Set-up.exe` não executado            | 🟢 **Baixo**    | Apague o ISO, monitore logs de rede por 30 dias                                         |
| Torrent baixado apenas                                 | 🟢 **Nenhum**   | Apague os arquivos                                                                      |

### 10.2 Ações Imediatas — Primeiros 30 Minutos

**Desconecte a máquina infectada da rede imediatamente.** Desplugue o cabo Ethernet e desative o Wi-Fi. Uma conexão C2 ativa pode estar em andamento. Cada segundo de conectividade é uma oportunidade para exfiltração adicional de dados ou entrega de payload secundário.

**Ainda não desligue a máquina se quiser evidências forenses.** Processos em execução e conexões de rede ativas documentam o comprometimento. Desligue apenas depois que a evidência for capturada ou se forense não for prioridade.

**De um dispositivo limpo e separado, altere todas as senhas importantes:** e-mail (endereços principal e de recuperação), contas bancárias e financeiras, senha mestra do gerenciador de senhas, contas de trabalho ou corporativas, serviços de armazenamento em nuvem, quaisquer chaves de API de serviços de desenvolvimento. Não use a máquina infectada para nenhum login até que ela esteja totalmente remediada.

**Bloqueie a infraestrutura C2 no roteador ou firewall:** resolução DNS e tráfego de rede para `i-odsports.com`, `104.21.5.5` e `172.67.132.177` devem ser bloqueados imediatamente.

### 10.3 Ações de Curto Prazo — Primeiras 24 Horas

**Revogue todas as sessões e tokens ativos:** conta Google (Segurança → Gerenciar dispositivos → Sair de todas as outras sessões), conta Microsoft, GitHub (Settings → Developer settings → Personal access tokens and OAuth Apps) e qualquer serviço acessado a partir da máquina infectada após a data em que o malware foi executado.

**Habilite autenticação multifator em todas as contas.** Use apps autenticadores baseados em TOTP (Google Authenticator, Authy ou Aegis) em vez de códigos por SMS, que são vulneráveis a ataques de SIM swapping. Gere códigos de backup e armazene-os a partir de um dispositivo limpo.

**Avise sua instituição financeira.** Explique que seu computador foi comprometido e solicite monitoramento aprimorado de transações. Revise transações recentes em busca de atividade não autorizada. Considere um congelamento temporário do cartão.

**Audite todas as extensões do navegador** no Chrome, Edge, Firefox e qualquer outro navegador instalado na máquina. O malware pode ter instalado extensões persistentes de coleta de credenciais. Remova qualquer coisa que não tenha sido explicitamente instalada por você.

**Verifique por software adicional instalado.** Execute `winget list` em uma janela do PowerShell e procure por qualquer pacote instalado por volta da data da infecção que você não reconheça. Pesquise programas instalados por "Planora" — remova-o se encontrado.

### 10.4 Remediação

**Opção A — Remoção manual (menos confiável):**

Pare e exclua os serviços maliciosos:

```powershell
Get-Service GoogleUpdaterInternalService* | Stop-Service -Force
Get-Service GoogleUpdaterInternalService* | Remove-Service
```

Exclua os diretórios do malware:

```powershell
Remove-Item "C:\Program Files\Google????_*" -Recurse -Force
Remove-Item "C:\Program Files (x86)\Google\GoogleUpdater\13*" -Recurse -Force
Remove-Item "C:\Program Files (x86)\Google\GoogleUpdater\14*" -Recurse -Force
```

Remova a chave DPAPI gravada pelo malware:

```powershell
Remove-Item "C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\941a2910-ceaf-4083-a069-04b1d985b6d1"
```

Limpe os logs do malware:

```powershell
Remove-Item "$env:TEMP\CreativeCloud" -Recurse -Force
```

> [!WARNING]
> Essa abordagem não pode garantir completude dada a profundidade do comprometimento. Hooks de API operam na fronteira do kernel e podem persistir após essas etapas.

**Opção B — Formatar e reinstalar (recomendado):**

Inicialize a partir de mídia externa preparada em uma máquina limpa. Apague a unidade do sistema com uma formatação completa (não rápida). Reinstale o Windows a partir da mídia de instalação oficial da Microsoft. Restaure apenas arquivos de dados — documentos, fotos, arquivos pessoais não executáveis — a partir de backups criados antes da data da infecção. Não restaure perfis de navegador, arquivos executáveis ou dados de aplicativos provenientes de backups infectados.

Uma reinstalação limpa do sistema operacional é o único método que fornece garantia verificável de remediação completa.

---

## 11. Conclusão

Esta análise documenta um infostealer profissionalmente engenheirado **confirmado em seis fontes independentes** — dados estáticos e comportamentais do VirusTotal, classificação MWDB, análise FileScan.IO, sandbox tria.ge, correspondência YARA do THOR APT Scanner e verificação C2 ao vivo. Ele evade com sucesso todos os principais motores de antivírus por meio de sete técnicas complementares: certificados roubados, obfuscação em múltiplas camadas, codificação ROT13, saídas limpas anti-VM, execução living-off-the-land, evasão baseada em tempo e camuflagem de C2. O malware exfiltra dados antes de o usuário ver a primeira tela do instalador e, em seguida, inicia o software legítimo da Adobe como cobertura, deixando a vítima sem qualquer indicação de que algo ocorreu.

Dois componentes permanecem não identificados no momento deste relatório: o aplicativo instalado silenciosamente via `winget install -h --id 9N411ZGN6M6G` e o payload secundário lançado como `Planora /INSTALL`. Eles são documentados como **comportamentos observados**, não como componentes maliciosos confirmados, porque seu conteúdo ainda não é público. Eles representam o limite externo do que as evidências disponíveis podem confirmar.

O servidor C2 foi registrado de forma proposital nove meses antes do início da distribuição e foi confirmado operacional em 9 de abril de 2026. O mesmo hash da DLL payload aparece em uma campanha paralela voltada a usuários de crack do Photoshop. Esta é uma operação sustentada, organizada e multi-produto — documentada, não inferida.

> [!CAUTION]
> **Zero detecções por antivírus não é evidência de segurança. É evidência de evasão.**
>
> Se este arquivo foi executado na sua máquina, siga as etapas de resposta a incidentes na Seção 10 e trate a máquina como comprometida até que se prove o contrário por meio de uma reinstalação completa do sistema operacional.

---

## 12. Referências e Índice de Fontes

Todas as descobertas neste relatório remontam a pelo menos uma fonte verificável de forma independente listada aqui. As alegações são categorizadas pelo tipo de evidência que representam.

### VirusTotal — Plataforma Primária de Análise

Todas as páginas de análise dos arquivos são públicas e acessíveis a qualquer usuário registrado por meio dos hashes fornecidos. A aba Behavior (dados de sandbox), a aba Details (metadados PE e informações da assembly .NET), a aba Community (análises de pesquisadores) e a aba Relations (pais de execução) são todas legíveis de forma independente.

* Set-up.exe: `https://www.virustotal.com/gui/file/3d20655679c8829a6baad001851905927ef1b826e3eea594b7be3f8331211e39`
* Installer.msi: `https://www.virustotal.com/gui/file/45415f110b7961eea726dd3b1c07ebed2bbc44d13e8d92d0d8bd1304ba145d73`
* SfxCA DLL: `https://www.virustotal.com/gui/file/06875058d4f40be9fb9d065bb4dbc29f67e80339ea261143d123d582c1481171`
* MSICustomActionDLL.dll: `https://www.virustotal.com/gui/file/487aca2bbd630c8013ee1992dabb970058c9a737c2fffce0c0a45801408771cd`
* Inteligência do domínio C2: `https://www.virustotal.com/gui/domain/i-odsports.com`

### MWDB — Malware Database (CERT Polska)

Amostra catalogada em 28 de fevereiro de 2025 pelo pesquisador `petik` — visível publicamente:

* `https://mwdb.cert.pl/file/3d20655679c8829a6baad001851905927ef1b826e3eea594b7be3f8331211e39`

### FileScan.IO — Análise Independente de Sandbox

Múltiplas análises independentes confirmando veredictos SUSPICIOUS e LIKELY_MALICIOUS:

* `https://www.filescan.io/reports/f6e3c4549690718297924317757db3941e9f282c0534d9ae1d20132d4f8d6659/7b3822d4-2620-4aca-8c4d-1f8d94462ac9`
* `https://www.filescan.io/reports/f6e3c4549690718297924317757db3941e9f282c0534d9ae1d20132d4f8d6659/a9eda77c-4e07-49ec-a283-6664a993213f`

### tria.ge — Sandbox Interativa

Análise comportamental confirmando características em tempo de execução:

* `https://tria.ge/250228-z9efqax1gx`

### MalwareBazaar / Malshare — Repositórios Públicos de Amostras

* Pesquisa MalwareBazaar pelo MD5 `e9d48daf4748eee45abf308b85e88b71`: `https://bazaar.abuse.ch/`
* Malshare: `https://malshare.com/sample.php?action=detail&hash=95ce97cd76fb08e07e005f3a419757b1`

### THOR APT Scanner — Feed YARA VALHALLA (Nextron Systems)

Cinco matches de regras YARA documentados em 11 de novembro de 2025:

* Regra Raccoon Stealer V2: `https://valhalla.nextron-systems.com/info/rule/MAL_Raccoon_Stealer_V2_Jul22_1`
* Pesquisa original do Raccoon Stealer V2 (AhnLab ASEC): `https://asec.ahnlab.com/en/35981/`
* Orientação da Nextron sobre limitações de atribuição YARA: `https://www.nextron-systems.com/notes-on-virustotal-matches/`

### Correspondências de Regras Sigma — GitHub SigmaHQ

Todas as regras Sigma disparadas estão publicamente disponíveis e podem ser pesquisadas:

* `https://github.com/SigmaHQ/sigma`

### Framework MITRE ATT&CK — Referências de Técnicas

* T1047 (WMI): `https://attack.mitre.org/techniques/T1047/`
* T1218 (System Binary Proxy): `https://attack.mitre.org/techniques/T1218/`
* T1055 (Process Injection): `https://attack.mitre.org/techniques/T1055/`
* T1497 (Virtualization/Sandbox Evasion): `https://attack.mitre.org/techniques/T1497/`
* T1056 (Input Capture): `https://attack.mitre.org/techniques/T1056/`
* Matriz ATT&CK completa: `https://attack.mitre.org/`

### Luca Stealer — Pesquisa de Base

* Documentação do Luca Stealer (Unit 42, Palo Alto Networks): `https://unit42.paloaltonetworks.com/`
* Análise do Luca Stealer pela AhnLab ASEC: `https://asec.ahnlab.com/en/36152/`
* Tag Luca Stealer do MalwareBazaar: `https://bazaar.abuse.ch/browse/tag/luca-stealer/`

### AvosLocker — Pesquisa de Base

* Aviso do CISA sobre AvosLocker (AA23-132A): `https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-132a`

### WiX Toolset — Referência de Framework Legítimo

O mecanismo SfxCA abusado na Camada 2 está documentado na documentação oficial do WiX:

* `https://wixtoolset.org/`

### WHOIS / Dados de Registro de Domínio

Data de registro de `i-odsports.com` (6 de fevereiro de 2025) verificável via:

* Consulta ICANN RDAP: `https://lookup.icann.org/`
* Aba de detalhes de domínio do VirusTotal (mesmo link da entrada do domínio C2 acima)

### uztracker.net — Postagem Original do Torrent

Contexto da descrição do pacote e da atribuição a m0nkrus:

* `https://uztracker.net/viewtopic.php?t=64297`

### Verificação ROT13

As decodificações da ofuscação da string de consulta WMI são matematicamente verificáveis com qualquer ferramenta ROT13:

* `https://rot13.com/` — insira `Jva32_PbzchgreFlffgrzCebqhpg` para verificar a decodificação para `Win32_ComputerSystemProduct`

---

*Data da Análise: 14 de abril de 2026*
*Todos os IOCs, hashes, nomes de domínio e endereços IP são fornecidos exclusivamente para auxiliar equipes de segurança e indivíduos na detecção e remediação desta ameaça específica.*
*Este relatório não contém código de exploração, ferramentas ofensivas ou instruções que permitam uso malicioso de qualquer tipo.*
*Licença: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — livre para compartilhar e adaptar com atribuição*
