# WORDLISTS — mesa do time (2026-10-19)

Fontes fornecidas pelo Kai; instaladas/validadas pelo maestro com evidência. Uso exclusivo em engajamento autorizado e laboratório.

## Instaladas

| Fonte | O que é | Caminho | Evidência |
|---|---|---|---|
| **SambaTu** | RockYou brasileira — senhas de vazamentos/infostealer logs (MIT, 488★) | `~/wordlists/sambatu/SambaTu.txt` | 2.140.468 linhas · 34M · sha256 `ebb84b5fe180885ddee12a1f6a0a048e5a48f4183e136e272f9eafd6e1fcd666` |
| **crunch** | Gerador de wordlist por máscara/pattern (C, crunchsec/crunch) | `~/Tools/crunch/crunch` → `~/.local/bin/crunch` | build local limpo; smoke `crunch 2 2 abc` OK |
| **CeWL** | Coletor de palavras de sites → wordlist dirigida ao alvo (digininja) | `~/Tools/cewl/cewl.rb` → `~/.local/bin/cewl` | CeWL 6.3.1; deps gems: getoptlong, spider, mini_exiftool, mime, mime-types, nokogiri, rexml, rubyzip, public_suffix + `perl-image-exiftool` |
| **weakpass.com** | Coleção massiva de wordlists públicas (download por lista) | referência remota | uso sob demanda; baixar + verificar hash; não commitar |
| **SecLists** | Base clássica geral (já instalada) | `~/wordlists` (2,5G) | — |

## Uso no engajamento

```bash
# SambaTu — campanha de senha BR (hashcat/john)
hashcat -a 0 -m 1000 hashes.txt ~/wordlists/sambatu/SambaTu.txt
john --wordlist=$HOME/wordlists/sambatu/SambaTu.txt hashes.txt

# CeWL — wordlist dirigida ao alvo vivo (autorizado)
cewl -d 2 -m 5 -w lista-alvo.txt https://alvo.example

# crunch — máscara por política de senha observada
crunch 8 10 -t 'P@ss%%%%' -o mascara.txt

# weakpass — lista grande sob demanda (verificar sha256 do download)
```

## Regras

- Nunca commitar listas no `~/MITR3` — só este índice.
- Hash antes do uso (SambaTu já selada).
- Seats: pedir ao maestro a lista certa para o alvo; não sair baixando coleções inteiras sem necessidade.
