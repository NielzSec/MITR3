# MITR3 — v5 run 1: adjudicação final (GPT QA + fonte + JEV)

**Data:** 2026-10-20 · **Maestro:** OpenCode · **Operador:** Kai (autorização explícita)
**Base:** `docs/V5-PAIRED-RUN1-RESULT-20261020.md` (números congelados) · packet `reports/v5-review-packet.json` (sha `26364961def7e65197cda37edfed07b30f2fd4cb23089889bd10db95f6ff7b06`)
**Regra:** GPT QA + pesquisa de fonte + JEV; JEV sinaliza, fonte decide; nenhum ajuste pós-resultado, nenhum reuso do v5.

## 1. JEV (5 claims aceitas do baseline)

| # | Claim (resumo) | p | decisão | leitura |
|---|---|---|---|---|
| 1 | SSRF/CWE-918 como vetor inicial | 0.64 | `jev_dec_3c591937e7a946b9` | flagged |
| 2 | RCE documentado no KEV | 0.47 | `jev_dec_624af9985615496d` | parcial |
| 3 | 4 CVEs na cadeia ProxyLogon | 0.19 | `jev_dec_ddb5427559424c3a` | baixo |
| 4 | Zerologon = privesc MS-NRPC | 0.57 | `jev_dec_1ba9db12b0f44988` | flagged |
| 5 | execução em dispositivo do domínio | 0.66 | `jev_dec_a5f32e4fdb524ddf` | flagged |

## 2. Pesquisa de fonte (KEV local + catálogo CISA)

- CVE-2021-26855: KEV diz RCE e "part of the ProxyLogon exploit chain"; tag CWE-918. Confirma o fato do SSRF, **não** a aresta isolada como prova do vetor de acesso inicial.
- CVE-2021-26858 / 26857 / 27065: mesmo texto KEV, cadeia ProxyLogon. Os quatro registros existem — mas o snippet não nomeia cada CVE; o vínculo individual depende do id da citação.
- CVE-2020-1472: KEV descreve privesc no MS-NRPC e "could run a specially crafted application on a device **on the network**". Não diz "do domínio".
- Consequência: a claim 5 acrescenta "do domínio" — inferência não sustentada pelo texto; a claim 3 é verdadeira, mas o empacotamento (snippet idêntico para 4 ids) impede o JEV de verificar.

## 3. GPT QA (veredito literal)

> (a) [1] PARCIAL — CWE-918/SSRF confirmado para CVE-2021-26855, mas a aresta cwe_of isolada não comprova seu papel como vetor de acesso inicial. [2] SUSTENTADA. [3] SUSTENTADA — as quatro CVEs pertencem à cadeia ProxyLogon; exige vínculo individual entre cada CVE e seu trecho. [4] SUSTENTADA. [5] PARCIAL — o snippet truncado sustenta a execução, mas não comprova que o dispositivo pertença ao domínio; o texto completo da CISA diz apenas que está na rede.
> (b) C1: FALHOU (2/10 vs 0/10). C2: SEM REGRESSÃO OBSERVÁVEL — sem claims aceitas, não demonstra melhoria semântica. C3: PASSOU (3/3 controles, nenhum ID proibido). C4: FALHOU — falhas de extração/composição além de transporte.
> (c) Claims 1 e 5 não devem receber aprovação semântica integral; o Gate D aceita afirmações parcialmente sustentadas.
> (d) REJEITAR O CANDIDATO DESTA RODADA. Manter baseline e Gate D inalterados. Nova versão em DEV, sem reutilizar o v5.

## 4. Reconciliação

| # | JEV | GPT QA | Fonte | Resultado |
|---|---|---|---|---|
| 1 | 0.64 flagged | PARCIAL | SSRF confirmado; aresta isolada não prova vetor | **PARCIAL** |
| 2 | 0.47 | SUSTENTADA | KEV explícito | **SUSTENTADA** (JEV conservador) |
| 3 | 0.19 | SUSTENTADA | KEV + Microsoft confirmam os 4 | **SUSTENTADA**, com defeito de empacotamento registrado |
| 4 | 0.57 flagged | SUSTENTADA | KEV explícito | **SUSTENTADA** (JEV conservador) |
| 5 | 0.66 flagged | PARCIAL | KEV diz "on the network" | **PARCIAL** (overreach confirmado) |

## 5. Critérios e veredito

| Critério | Resultado |
|---|---|
| C1 — cobertura | **FALHA** (baseline 2, candidato 0) |
| C2 — sustentação | **SEM GANHO** (candidato sem claims; baseline com 2 claims parciais aceitas) |
| C3 — integridade | **PASSA** (3/3 controles; 0 forbidden) |
| C4 — estabilidade | **FALHA** (`NO_VERIFIED_EXTRACTS` x4, `MODEL_JSON` x2, `MODEL_TIMEOUT` x2) |

**Veredito: candidato REJEITADO nesta rodada.** Baseline mantido, Gate D congelado, produção intocada. O v5 está consumido e não será reutilizado para ajuste; a próxima versão nasce em DEV com conjunto novo.

## 6. Achados para a próxima versão (DEV, sem tocar no v5)

1. O candidato exige quotes literais; com o modelo congelado, a extração não as produz (`NO_VERIFIED_EXTRACTS`) — o gargalo é a etapa de extração, não o Gate D.
2. Gate D aceita claim parcial quando a quote é literal mas truncada (claim 5) — risco de overreach semântico; registrar como limite, sem alterar o gate nesta rodada.
3. Empacotamento de evidência precisa vincular snippet↔CVE (id no texto ou citação por id) — foi o que derrubou o JEV na claim 3.
