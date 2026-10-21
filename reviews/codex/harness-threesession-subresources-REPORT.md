# Sub-recursos — relatório offline para Maestro VANTA

UTC: 20261021T211135Z. **32/32 pytest PASS; exit 0** (23 anteriores + 9 novos).
Python 3.14.8 / pytest 9.1.1 local, sem instalação/download. Executado em
bubblewrap `--unshare-net`, raiz somente leitura; plugins externos/cache
inativos e sockets/DNS bloqueados na suíte. Zero tráfego MELI.

## Mudança

`Runner` admite somente pedido principal ou selectors `shipments`, `billing_info`,
`notes`. Mantém GET, transporte fake obrigatório, origem `.example.test`, três
identidades distintas e mesmo pedido sintético. Cada cenário usa seis chamadas
falsas, serialmente, sem retries. Não há CLI live ou carregamento de credenciais.

| Rota modelada | Controles A/C | B 403/404 sem dados | B com campos vinculados |
|---|---|---|---|
| `/orders/{id}/shipments` | 200, envio/endereço sintéticos A–C | NEGATIVE | BOLA_CANDIDATE |
| `/orders/{id}/billing_info` | 200, documento fiscal sintético A–C | NEGATIVE | BOLA_CANDIDATE |
| `/orders/{id}/notes` | 200, notas compartilhadas; privadas só em C | NEGATIVE | BOLA_CANDIDATE, inclusive nota exclusiva de C |

Envelopes normalizados de fixtures vinculam `order_id`, buyer A e seller C;
não são schemas oficiais capturados. `seller_notes` é política DO MODELO.
Exposição dessas notas no controle A interrompe a execução. O baseline incorpora
campos exclusivos de C para também detectar seu vazamento para B.

Cobertura nova: autorização correta no pedido principal e desacoplada no
sub-recurso; vazamento apesar de 403/404; vínculo de pedido/ator incorreto;
controle vazio/malformado; 200 genérico; negação com conteúdo aninhado desconhecido;
selector fora da allowlist; preservação de hashes e ausência de valores privados
na saída. Negação com dados nunca vira NEGATIVE. Os 23 testes anteriores passam.

## Staging e concorrência

O teste do trio C1/C2/X1 foi ajustado para permitir arquivos adicionais de outras
lanes no diretório. Preserva todas as verificações do trio (método, rota, host,
User-Agent, Accept, tokens e corpo); não emite aprovação estrutural dos novos.
Na inspeção inicial seis novos templates não tinham CRLF CRLF final. Outra lane
alterou esses arquivos durante a coleta `harness-subresources-20261021T211055Z`;
o selo daquela coleta foi bloqueado por mudança de hashes. Nesta execução os
inputs permaneceram estáveis. Templates não foram editados por Codex.
Checagem final de bytes CRLF: todos os templates presentes conformes.

## Limites

O threat model local marca `/orders/{id}/billing_info` como legado/depreciado;
modelado por solicitação, sem afirmar suporte atual. Dados, schema e política de
visibilidade são sintéticos. PASS prova comportamento do simulador, não BOLA real,
permissões reais da API ou aprovação live QA/JEV. Os cenários independentes não
constituem autorização para somar seu tráfego numa onda real.
Relatórios e manifestos anteriores preservados; hashes novos abaixo. Handoff no
chat/workspace, sem alegar ACK remoto Maestri.

## SHA-256

- `85689aec99c759b911c3dee5a92e8f0309b6649cbf0c6eee8b799f3a518ee8ab` — `bin/mitr3-threesession.py`
- `9759b8d9497e605563e6d0e1914d581cef24c94439e89686962f70d28eca7ce9` — `tests/test_threesession.py`
- `437ede737cdeadc500f506b67cd8bdcc2d26c82dbd2613b83eb42fddc567e07c` — `docs/H1-MELI-SPEC-V10.md`
- `889c6524bccce3fe4635308481aa880cd745ad6ecb7b40b1e12b11e1bc2d7870` — `docs/H1-MELI-THREAT-MODEL-CODEX-WEB-20261021.md`
- `8880f28496a9eb50ced7fe65dca3bcd3dd75a6368a924d46f144293d7065bf0f` — `engagements/burp_lane/h1_meli_onda10/templates/C1_billing_info_comprador-A.req`
- `2aadaee593c9c0b46ccd8b955c80fd8451036403e6adcdf482e2286d56bc3586` — `engagements/burp_lane/h1_meli_onda10/templates/C1_comprador-A-le-pedido.req`
- `51dd01c62f1d0f257907f9f67700b33cf29254ceffeccd800f465961c45f59e3` — `engagements/burp_lane/h1_meli_onda10/templates/C1_shipments_comprador-A.req`
- `e4444b5ba12edb2d1e2a0dc2de8e52c069a63cb784a11c7136fda94e1003fe70` — `engagements/burp_lane/h1_meli_onda10/templates/C2_billing_info_vendedor-C.req`
- `01486dfc44d321ccd05a8c3dea9578444536587c8fc7eb7b684e6cb6b8162e0a` — `engagements/burp_lane/h1_meli_onda10/templates/C2_shipments_vendedor-C.req`
- `893b2f82620cd573cdcd77e958bd4379fb3701f004284464a6ad1ccab45b6e6d` — `engagements/burp_lane/h1_meli_onda10/templates/C2_vendedor-C-le-venda.req`
- `2ae41e79f3d7e7a55ccc87df4170e9dc2f93de13c1f247d9ea3a6ebe27d9375a` — `engagements/burp_lane/h1_meli_onda10/templates/X1_billing_info_terceiro-B-pedido-A.req`
- `97f06c57653eee93656ae6f1b9b7cd0393585881eb971da61a90359cef343e91` — `engagements/burp_lane/h1_meli_onda10/templates/X1_shipments_terceiro-B-pedido-A.req`
- `b6044998b42ea624f89de00985ed30172ad267dc2610f63f96d5eb4f89368537` — `engagements/burp_lane/h1_meli_onda10/templates/X1_terceiro-B-le-pedido-de-A.req`
- `ef37e60e1efa836518ff1ad7a53d5d9d5abf32360e3d7968b329e35d8dd5ea21` — `reviews/codex/harness-subresources-20261021T211135Z/command.json`
- `c4e829428d7b4008a59fde995012e1f2ec44911adb621225441de6c2ba99a153` — `reviews/codex/harness-subresources-20261021T211135Z/inputs-unchanged.json`
- `8c48e7232b1a5a9a9fa195ee65ea5c49d1172ae7b961b02f75201b8d9f00106a` — `reviews/codex/harness-subresources-20261021T211135Z/inputs.sha256.json`
- `9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa` — `reviews/codex/harness-subresources-20261021T211135Z/pytest.exit`
- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` — `reviews/codex/harness-subresources-20261021T211135Z/pytest.stderr`
- `a2922a7ba2bc5383eecfb82967ddb685344a0b0b5897af69593a21659d19d913` — `reviews/codex/harness-subresources-20261021T211135Z/pytest.stdout`

Reprodução: comando/ambiente em `reviews/codex/harness-subresources-20261021T211135Z/command.json`.
