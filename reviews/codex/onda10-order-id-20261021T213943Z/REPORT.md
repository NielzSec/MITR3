# Onda 10 — --order-id

38/38 testes PASS. CLI dry-run confirmada em três invocações: default,
ID mínimo de 8 dígitos e ID alternativo com suite all. Cada execução validou
nove templates, sem rede. Sandbox bubblewrap --unshare-net, raiz somente
leitura e /tmp privado; credenciais sintéticas, nenhum token real lido.

--order-id mantém default 2000015638831799. prepare valida ASCII [0-9]{8,}
antes de acessar templates/credenciais, emitindo Stop('INVALID_ORDER_ID').
O argumento segue por prepare, execute e classify sem alterar estado global.
Testes cobrem interpolação das nove rotas, ownership nos três recursos,
rejeição do pedido antigo quando outro é selecionado, limite de oito dígitos,
ID curto, letras, sinais, espaços, Unicode, query/path e injeções CRLF.

Código/testes estáveis durante a coleta. Hashes em MANIFEST.sha256; selo em
MANIFEST.sha256.sha256. Relatórios anteriores preservados como snapshots históricos.
Sem live ou nova adjudicação QA/JEV; autorizações operacionais continuam externas.
