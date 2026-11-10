# MITR3 — Doutrina de pesquisa e QA (destilada do GPT-6 / GPT QA)

**Data:** 2026-10-21 · **Origem:** handoffs do GPT-6 (arquivo/Remote Desktop) + portal GPT QA
(`chatgpt.com/c/6ad81389…`), consolidados pelo maestro OpenCode.
**Uso:** leitura obrigatória antes de abrir qualquer lane de caça. Este documento ensina **como
procurar falha**, não autoriza tráfego. Quem emite tráfego é o OpenCode, sob os gates vigentes.

---

## 1. O loop do pesquisador (não é checklist, é ordem de raciocínio)

```
Observação → Hipótese (qual limite de confiança?) → Variável isolada → Controle válido
→ Experimento mínimo → Evidência por identidade/efeito → Falsificação → Conclusão → Status
```

Regra dura: **nenhuma etapa pode ser pulada por entusiasmo**. O erro clássico do MITR3 não foi
falta de ferramenta — foi promover hipótese a achado sem discriminante (ver §4, `address_id`).

## 2. O que NUNCA é prova

| Sinal | Por que não prova | O que ainda falta |
|---|---|---|
| HTTP 200 | Pode ser no-op, fallback, erro lógico encapsulado | efeito observável e atribuível |
| 200 com `events: []` / `execute_events` | Aceite de forma, sem mudança de estado | leitura independente do estado depois |
| ID refletido no HTML/DOM | Eco de parâmetro, não origem do objeto | campo de dono no JSON (`userId`) ou correlação independente |
| Texto visível igual | Dois objetos distintos podem ter rótulos iguais (foi o falso positivo do `address_id`) | ID do objeto + dono |
| 400/403 no cruzado | Pode ser incompatibilidade de payload, não ACL | controle positivo **200 com payload legítimo** primeiro |
| 404 na rota direta | Pode ser rota quebrada, não ACL | controle positivo do dono na mesma rota |
| Precedente público/CVE | Não concede autorização nem garante que o alvo tem a falha | reachability real no alvo |

**Regra de ouro do QA:** em JSON, a prova é o **campo de origem** (`userId`, `owner_id`,
`account_id`), não o eco do ID que você mandou. Em renderização, prova é o **ID do objeto**.

## 3. Contrato de evidência por caso

```
identidade efetiva (quem fala) → ID do objeto e dono → controle legítimo (200 + estado)
→ único diferencial (troca de ID/param) → efeito ou ausência de efeito lida por identidade
→ fonte do dado (server-side?) → hash SHA256 + timestamp UTC
```

Se qualquer elo faltar, o status é `INCONCLUSIVE`, não "quase um achado".

## 4. Estudo de caso interno — o `address_id` retratado

- Observado: review do B exibia endereço com os mesmos rótulos do A.
- Hipótese: BOLA de leitura no checkout.
- **Falsificador aplicado:** o objeto exibido era `1683263260`, do **próprio B**, criado com
  rótulos iguais aos do A. A recebia 404 nele.
- Conclusão: falso positivo, **retratado**, sem submissão.
- Lições que viraram regra:
  1. test data dos dois lados tem de ser **distinguível desde a criação**;
  2. prova por ID/dono, nunca por texto;
  3. retratação é entrega, não vergonha — proteger o programa é parte do trabalho.

## 5. Falsificadores obrigatórios (checar antes de dizer "achado")

cache/CDN · HTML genérico · body que só reflete o ID · fallback para objeto próprio ·
dados duplicados entre contas · vínculo legítimo entre A e B · 200 com erro lógico ·
no-op silencioso · perda de sessão · backport/versão diferente · feature flag · comportamento
por design documentado.

## 6. Precedente antes de investir (economia de tempo)

`python3 bin/mitr3-casebook.py search "<tema>"` e `show <id>`.

Precedente que já queimou lane: **HackerOne MercadoLibre #2495989** (mai/2024, divulgado
mar/2025) — cancelamento de vendas de **outros vendedores**. Toda hipótese de H-CANCEL deve ser
comparada a ele **antes** do probe, sob risco de duplicata. A publicação original não está
integralmente acessível; **não inventar endpoint/PoC**.

## 7. PoC mínima: permitida; exploit público: não é licença

- HackerOne autoriza PoC responsável dentro da política específica; o limite é **impacto além do
  necessário**, não "usar exploit é proibido".
- CVE/exploit público conhecido **não** autoriza execução: alvo elegível + técnica dentro da
  política + PoC mínima.
- Test users oficiais elevam o teto (`PR:H` no snapshot MELI), não removem o dever de mínimo
  efeito.
- Proibido no mandato: pagamento real, conta de terceiro, enumeração/brute force, DoS,
  engenharia social, dump, bypass de SSO/IAP, host OT/RFC1918.

## 8. Gates e disciplina de tráfego

- **OpenCode é o único emissor** de tráfego ao alvo; agentes trabalham offline ou por leitura de DOM.
- Tetos: 60 req/host/h, manual, serializado, uma sessão; ledger antes/depois de cada rodada.
- Parada imediata: 429, 403 inesperado, WAF, 5xx persistente, PII de terceiro, degradação,
  mudança de escopo, risco financeiro.
- Aprovação de fase: **QA + JEV** (sem gate humano desde a emenda); mudança de requisito volta à spec.

## 9. Contrato de resposta entre agentes

`[SOURCE]` proveniência e autoria · `[REAL_THINKING]` vs `[RECONSTRUCTION]` nunca misturados ·
`[TRUST_BOUNDARY]` permissão vs objeto/atributo · `[MITR3_MATCH]` evidência no alvo ou
`NO_EVIDENCE` · `[SAFE_DISCRIMINATOR]` controle/refutação · `[PROOF_GAP]` o que falta ·
`[FP_RISK]` fallback/cache/duplicata · `[STATUS]` `STUDY_ONLY | HYPOTHESIS | INCONCLUSIVE |
NEGATIVE_VARIANT | CANDIDATE_PRIMARY | HUMAN_APPROVED` · `[DUPLICATE_CHECK]` · `[NEXT_OWNER]`.

## 10. Estado corrente das lanes (2026-10-21)

| Lane | Status | Discriminante que fechou/abriu |
|---|---|---|
| L1 `update_selection` | **NEGATIVE_VARIANT** | controle B→B 200 `execute_events` com body de `localStorage`; cruzado A→B 400 `review_technical_error` na mesma origem com CSRF válido ⇒ sessão amarrada ao dono. Refutada a hipótese de `Origin/Referer`. |
| `address_id` (L-B3) | **RETRATADO** | objeto exibido era de B |
| API `/users/{id}/addresses` | **fechado por policy** | 403 PolicyAgent no próprio A |
| L-B2 `config_id`/`combination_id` | **em teste (próprio checkout)** | aceitar config/combinação não ofertada e **persistir efeito** = candidato; normalização server-side = negativo |
| H-CANCEL | **bloqueado por duplicata** | #2495989 |

## 11. Como agir como pesquisador (o resumo que o GPT pediu)

1. Escolha a **variável**, não a ferramenta. O que estou mudando? Quem deveria validar?
2. Construa o **controle** antes da mutação — sem 200 legítimo, 400 cruzado não significa nada.
3. Prefira o **discriminante mais barato**: leitura de estado > escrita > cadeia.
4. Escreva o **falsificador** antes do experimento: qual resultado me faz desistir?
5. Um único diferencial por request. Se mudou duas coisas, você não aprendeu nada.
6. Registre **antes/depois**, hash, UTC, e o que o servidor recalculou.
7. Se o servidor normaliza, **encerre a lane na hora** e diga isso em voz alta.
8. Se confirmar, **minimize**: o relatório vale pelo efeito reproduzível, não pelo dano.

---

**Natureza:** artefato de método e QA. Não é autorização de execução nem evidência de
vulnerabilidade.
