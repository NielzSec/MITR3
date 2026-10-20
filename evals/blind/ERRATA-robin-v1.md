# Errata — `blind-answers-robin-v1`

**Data:** 2026-10-20 · **Arquivo congelado:** `evals/blind/blind-answers-robin-v1.json`
(sha256 `61bf0b511faa00d98b89635b2c807dcbe675b6a070cafa5b51eef63bb2a40693`)

O arquivo **não foi editado**. Esta errata registra o que a primeira rodada descobriu
sobre o próprio gabarito.

## Item `blind-robin-07`

**Pergunta:** "Hosts ESXi encriptados me remetem ao ransomware ESXiArgs. Qual CVE
catalogada do vCenter é a âncora pública dessa campanha?"

**Gabarito v1:** `expected_ids: ["CVE-2021-21974"]`, `abstain: false`

**Correção:** `CVE-2021-21974` **não existe no catálogo CISA KEV.** Verificado em dois
lugares independentes:

| fonte | resultado |
|---|---|
| cache local `knowledge/reference-datasets/cache/cisa-kev.json` | 1.748 CVEs, `CVE-2021-21974` ausente |
| feed oficial ao vivo (`known_exploited_vulnerabilities.json`) | 1.748 CVEs, catalog `2026.10.16`, ausente |
| mesmo feed | `CVE-2021-21972`, `-21973`, `-21975` presentes |

A campanha ESXiArgs é pública e usou a falha de OpenSLP do ESXi, mas ela não foi
adicionada ao KEV. Portanto **nenhuma fonte do corpus sustenta a pergunta**, e a
resposta correta é abstenção — não um ID.

**Correção aplicada:** o item passa a valer como `abstain: true`, `expected_ids: []`,
com `forbidden_ids: ["CVE-2021-21972"]` (o CVE de vCenter que existe no KEV e seria
o erro plausível de quem responde de memória).

Isso reduz o conjunto de itens respondíveis de 7 para 6. O teto com compreensão de
consulta passa a ser **6/6**, e o piso continua **0/6** — o sistema hoje abstém nos
seis, o que é honesto mas não é resposta.

## O que isso ensina sobre o método

O erro estava no gabarito, não no sistema. Um conjunto cego escrito de memória por
quem viveu o trabalho **também erra**. A diferença é que o erro foi pego por
verificação contra a fonte primária, antes de qualquer ajuste no mecanismo — e o
arquivo congelado permaneceu congelado.

Toda expectativa de ID em conjunto cego deve passar por essa checagem: o ID existe
de fato no corpus citado?
