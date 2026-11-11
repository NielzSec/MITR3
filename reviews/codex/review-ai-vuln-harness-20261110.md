# Pacote de Revisão Independente — AI Vulnerability Harness
**Destinatário:** Codex CLI (assim que a cota da sessão for restabelecida)  
**Autor:** VANTA (Antigravity)  
**Data:** 10/11/2026  
**Status:** Pronto para Revisão por Agente Independente  
**Diretiva do Operador:** Github gerenciado por agente dedicado; revisão estritamente local e offline.

---

## 1. Contexto da Criação

Durante a pausa de cota do Codex, foi implementada a arquitetura do **AI Vulnerability Harness** no MITR3, fundamentada na doutrina de triagem progressiva e mitigação estrutural (*AWS AI Vulnerability Harness Architecture*, 2026).

O objetivo do motor é atuar como gate determinístico contra falsos positivos e alucinações de modelos de linguagem antes de qualquer revisão humana ou tentativa de exploração.

---

## 2. Artefatos para Revisão

| Artefato | Caminho | Função |
| :--- | :--- | :--- |
| **Especificação Técnica** | `docs/MITR3-AI-VULNERABILITY-HARNESS-SPEC.md` | Doutrina das 3 camadas, fórmula de risco, tabela de multiplicadores IaC e steering contract. |
| **Motor Central** | `bin/mitr3-vuln-harness.py` | CLI stdlib Python: consenso multi-scanner, AST Gate (Python/JS) e parser de IaC (Terraform/CloudFormation). |
| **Contrato de Steering** | `hackbots/contracts/harness-steering.schema.json` | Schema JSON que impede autoaprovação e exige evidências físicas SHA256. |
| **Suíte de Testes** | `tests/test_vuln_harness.py` | 8 testes unitários cobrindo quarentena, consenso, rejeição por AST, aceitação de sinks e multiplicadores de IaC. |

---

## 3. Checklist de Auditoria para o Codex

1. **Camada 1 (Multi-Scanner):**
   - Validar se a correlação espacial ($\pm 5$ linhas) e a normalização de paths são resilientes a caminhos relativos/absolutos.
   - Confirmar se o status `QUARANTINE` (0.8x) e `CONFIRMED_BY_ENSEMBLE` (1.5x) tratam corretamente entradas isoladas do Semgrep, CodeQL e Trivy.
2. **Camada 2 (AST Gate):**
   - Inspecionar a classe `PythonASTInspector` em `bin/mitr3-vuln-harness.py`: garantir que a árvore sintática detecte funções aninhadas, classes e sinks sem falso negativo para chamadas dinâmicas ou métodos de atributos.
   - Conferir se a detecção de comentários e linhas vazias elimina eficazmente injeções de prompt contidas no código-fonte.
3. **Camada 3 (IaC Context):**
   - Conferir se as regras regex de `scan_iac_context` identificam com precisão WebACLs WAF, JWT Authorizers e subnets privadas sem falsos positivos em variáveis comentadas.
4. **Interligação com a Engenharia de Grafos (Próxima Etapa com GPT):**
   - Avaliar a interface de exportação dos nós do Harness para o grafo de ataque do MITR3:
     - Nó `Finding` $\rightarrow$ Nó `Function/AST` via relação `:CALLS` ou `:REACHES_SINK`.
     - Nó `Finding` $\rightarrow$ Nó `IaCControl` via relação `:MITIGATED_BY`.

---

## 4. Comando de Reprodução dos Testes Locais

Execute na raiz `~/MITR3`:

```sh
python3 -m unittest discover -s tests -p "test_vuln_harness.py" -v
```

Resultado atual de referência: `Ran 8 tests in 0.004s — OK`.
