# Correção e Atualização de Atribuição — m0nkrus

---

## Resumo Rápido

Eu errei. Associei suas releases a um infostealer sem evidências suficientes para isso — **usar o seu arquivo não é o mesmo que ter envolvimento nisso**, e eu deixei essa distinção passar completamente.

O que você disse bate: os checksums são seus, e o `installer.msi` que você mencionou não existe em nenhum dos seus repacks. O infostealer é real, mas quem o distribuiu foi outra pessoa, usando o seu `setup.exe` legítimo como fachada. O rocket1337 analisou o pacote corretamente e de boa-fé. A decisão errada foi minha.

**O m0nkrus não tem nenhuma conexão com isso. Suas releases são limpas. Estou corrigindo o relatório. Se quiser que o repositório e tudo associado a ele seja removido, basta responder ao seu comentário mais recente na página do Illustrator 30.3 do seu site — especificamente a mensagem do usuário "the name" — e saberei que você está se referindo a isto. Isso é suficiente.**

---

# Versão Completa

Eu errei — especificamente na parte da origem dos arquivos. Associei coisas que não tinham conexão real. A maior parte veio de dados públicos, e eu não parei para questionar uma associação que deveria ter questionado. Já estava no meio da correção quando o m0nkrus comentou.

---

## Sobre a Resposta do m0nkrus

Os dois pontos se sustentam. *"The checksums for my file are listed there"* — sim. *"It says it uses a certain Installer.msi. Can you find it in my repacks?"* — não, porque ele não existe. Não há nenhum `installer.msi` em nenhuma das suas releases, e esse foi o sinal mais claro que eu passei direto.

O infostealer é real. Mas o m0nkrus não o criou nem distribuiu. **O fato de alguém ter usado o arquivo dele não o torna responsável pelo que foi empacotado junto**, e eu não deixei isso claro na análise original. A única ligação entre o trabalho dele e esse infostealer é que o agente malicioso usou a release dele como cobertura — sem o conhecimento dele — para dar ao pacote uma aparência legítima.

---

## Como a Atribuição Incorreta Aconteceu

O infostealer pode ser rastreado até esta postagem no Reddit:
[https://www.reddit.com/r/huion/s/GNW09xTEve](https://www.reddit.com/r/huion/s/GNW09xTEve)

O usuário **Onep2** já tinha sinalizado o comportamento suspeito na época:

> *"Be careful with that crack, because it's a bit dodgy. During installation, there's a point where it asks for administrator permissions to 'make changes', but it never specifies what's being installed or why. It doesn't mention Photoshop at all during that step. The most suspicious thing is that if you cancel that request, the installation carries on regardless without any problems. If that permission were really necessary to install Photoshop, you'd normally expect it to fail or stop, but that doesn't happen. That suggests that the permission is actually for installing other things on the side, without you knowing. After installing it, a programme called 'Planora' appears on the system — never mentioned during the process. I don't have the advanced knowledge to analyse everything it does in the background, but these behaviours alone are enough to raise serious concerns."*

A postagem tinha três links:

1. Um link para a Adobe
2. Um download via **MediaFire** — plataforma que o m0nkrus nunca usou para distribuição, o que por si só já deveria tê-lo descartado
3. Uma página do VirusTotal com os resultados do hash do arquivo analisado

Esse hash é do `setup.exe` legítimo do m0nkrus. O distribuidor malicioso o empacotou junto com o infostealer para fazer o pacote parecer limpo.

O rocket1337 encontrou o pacote, baixou, identificou o infostealer e publicou os resultados nessa mesma página do VirusTotal — a que já estava linkada no post do Reddit, assim como fez com os outros arquivos da cadeia. O `setup.exe` é genuinamente do m0nkrus. Foi só usado como cobertura. Com aquele link do VirusTotal bem ali no post, era uma leitura razoável. Eu encontrei esse envio depois, vi o hash associado à cadeia, e segui com isso sem parar para perguntar como ele tinha chegado ali.

---

## Para Deixar Claro

| Entidade       | Situação                                                                  |
| -------------- | ------------------------------------------------------------------------- |
| **m0nkrus**    | Sem nenhuma conexão com o infostealer. Suas releases são limpas.          |
| **rocket1337** | Sem culpa. Analisou corretamente e de boa-fé.                             |
| **Eu**         | Associei elementos sem conexão e publiquei sem verificação suficiente.    |

---

## Nota Direta ao m0nkrus

Você tem todo o direito de estar insatisfeito. Te acusei incorretamente, e não estou aqui pedindo simpatia ou passagem livre — eu sou o que errou aqui.

Se quiser que o repositório suma, é só falar. Responda aqui ou na discussão do Illustrator 30.3 e eu removo. É a única coisa concreta que posso fazer agora, e a decisão é sua.
