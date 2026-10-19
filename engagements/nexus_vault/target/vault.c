// language: C, file: vault.c, target: linux x86_64 — alvo de treino do pipeline Nexus
// Objetivo: menu com read() de tamanho errado; existe uma função win() não referenciada.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static void win(void) {
    puts("ACESSO CONCEDIDO — flag: MITR3{v4ult_r0p_4nd_ev1d3nce}");
}

static void vuln(void) {
    char buf[64];
    puts("Digite o código do cofre:");
    fflush(stdout);
    read(0, buf, 512);          /* overflow: 512 em um buffer de 64 */
    printf("Código registrado: %s\n", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== Cofre MITR3 ==");
    vuln();
    puts("Acesso negado.");
    return 0;
}
