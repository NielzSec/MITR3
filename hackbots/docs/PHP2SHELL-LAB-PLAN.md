# MITR3 — PHP2Shell / laboratório futuro de CVEs (NÃO IMPLANTADO)

**Estado:** RESEARCHED / LAB_SPEC_ONLY / VULNERABLE_RUNTIME_NOT_STARTED.
Pesquisa documental em 24/10/2026. Nenhum pull de imagem, serviço, exploit ou
instância Docker com PHP vulnerável foi iniciado nesta tarefa.

## Vídeo de referência
- Vídeo do operador: https://youtu.be/SP7y1h0laN0
- Metadados públicos YouTube oEmbed: **php situation 24h later**, LiveOverflow.
- Descrição pública: analisa alegações sobre PHP2Shell e demonstra RCE em
  PHP/Apache e WordPress. O vídeo e a descrição não devem ser tratados como
  prova de que um único PoC funciona com todas as SAPIs/configurações.
- Foco do futuro piloto: duas CVEs com mecanismos distintos.

## Vulnerabilidades confirmadas pelo fornecedor
| CVE | Mecanismo de alto nível | Estado em 24/10/2026 |
| --- | --- | --- |
| CVE-2026-109618 | Interrupção OOM com dados internos parcialmente inicializados; corrupção de memória | Corrigida em branches suportadas |
| CVE-2026-109619 | Estado global da requisição aponta para memória já liberada (use-after-free) | Corrigida em branches suportadas |
| CVE-2026-115560 | Vetor diferente, raro, ligado a session upload progress + troca de serializador em runtime | Advisory informativo em 23/10; correção futura ainda não atribuída |

Versões corrigidas upstream em **21/10/2026**: PHP **8.5.12,
8.4.27, 8.3.36, 8.2.35**. Exemplos de pares a avaliar: 8.4.26
(potencialmente vulnerável) versus 8.4.27 (corrigida).
**Não presumir que o tag Docker antigo exista ou que o pacote de uma
distribuição sem número upstream equivalente esteja vulnerável**:
consultar SHA256 do digest de cada imagem, `php -v`, SAPI e changelog.

Fontes:
- PHP oficial: https://www.php.net/archive/2026.php
- PHP security advisories:
  https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
  https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- CERT-EU 2026-018: https://cert.europa.eu/publications/security-advisories/2026-018
- CTIR.gov.br alerta 93/2026:
  https://www.gov.br/gsi/pt-br/assuntos/ctir/alertas/2026/alerta-93-2026
- Docker PHP2Shell guidance:
  https://www.docker.com/blog/security-update-on-php2shell-impact-for-docker-customers/

## Ambiente de laboratório proposto — gates obrigatórios
**Recomendação:** Docker **dentro de VM Linux descartável**, não no Arch
principal com Morfeus e MegaBrain. Container compartilha o kernel; o grupo
`docker` de nielz concede alto privilégio ao daemon do host. Um PoC recente
de RCE + corrupção de memória exige cautela extra.

Plano para revisão e autorização específica antes de ligar:
1. VM isolada, snapshots de reversão, sem credenciais, API keys, tokens,
   Tailscale, Docker socket, drives ou diretórios pessoais montados.
2. Escolher uma CVE **e uma SAPI** por experimento; para comparação de
   LiveOverflow começar investigando `Apache mod_php`, não substituir
   silenciosamente por `php -S` ou PHP-FPM.
3. Imagens/compilações vulnerável e corrigida **imobilizadas por digest**,
   verificando tag, PHP `php -v`, extensões e parâmetros equivalentes.
   Rejeitar `latest` e Dockerfile que baixa artefatos mutáveis.
4. Privilégios mínimos: sem `--privileged`, sem Docker socket, sem
   host network, sem mounts do host, `cap_drop: ALL`, `no-new-privileges`,
   seccomp padrão, rootfs read-only se compatível, tmpfs limitado,
   usuário sem privilégios, memória/PIDs/CPU e timeout.
5. Restrição de egress na **VM/firewall**; expor HTTP somente na interface
   loopback da própria VM. Bloquear conexões do lab a produção, LAN e internet.
6. Primeiro observar versões, comportamento HTTP não agressivo e logs.
   Só depois de revisão do PoC e de autorização explícita executar uma
   reprodução técnica controlada **apenas no alvo descartável**, com limites
   de tempo/memória, sem shells persistentes, sem saída da VM e parada manual.
7. Comparação controlada vulnerável x corrigida, usando a mesma configuração;
   coletar resultados sintéticos, status, logs, métricas, exit codes,
   crashes e evidência de efeito **somente no guest**.
8. Final: desligar/remover container e VM; registrar versões, digests,
   diferenças observadas, relatório de risco e protocolo de cleanup.

## Relação com Hackerbots
- Primeiro manter **pesquisa defensiva estruturada** de CVEs / patches;
  o Research Hackerbot pode produzir relatório com fontes oficiais e versões.
- O Web Hackerbot futuro poderá revisar **artefatos offline de laboratório**.
- Fuzzing/Reverse Engineering só após benchmark de segurança e escopo.
- Morfeus não recebe acesso ao socket Docker nem a ferramentas de deploy.
- F01 (custódia entre UIDs): OPEN; perfis LLM e execução de alvos
  não habilitados. QA independente e aceite humano ainda requeridos.
- Ausência de PoC real agora não impede planejar o benchmark e os oráculos.
