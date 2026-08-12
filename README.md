# F5 BIG-IP TLS Validator

Script Python para **validação automatizada de configurações TLS** em dispositivos F5 BIG-IP via API iControl REST. Gera relatório HTML detalhado com achados de segurança e comparativo de pré e pós validação.

---

## Funcionalidades

- Conexão autenticada via API REST iControl (token-based)
- Análise de todos os `client-ssl` e `server-ssl` profiles de uma partição
- Validação de Virtual Servers e seus profiles SSL associados
- Geração de relatório HTML com severidade por finding
- Comparativo automático **Pré vs Pós** validação (delta)
- Salvamento de baseline em JSON para auditoria

---

## Validações Realizadas

| Categoria | O que é verificado |
|---|---|
| **Protocolos** | TLSv1.0, TLSv1.1, SSLv2, SSLv3 ativos ou não bloqueados |
| **TLS 1.3** | Se está explicitamente habilitado |
| **Ciphers** | RC4, DES, 3DES, MD5, NULL, EXPORT e outros algoritmos fracos |
| **Certificado** | Dias para expiração (alerta ≤ 90d, crítico ≤ 30d) |
| **Chave** | Tamanho mínimo (RSA ≥ 2048 bits, ECDSA ≥ 256 bits) |
| **Renegociação** | Renegociação TLS habilitada / `secure-renegotiation require-strict` |
| **Virtual Servers** | Presença de profile SSL associado |

### Severidades

| Nível | Descrição |
|---|---|
| `CRITICO` | Risco imediato — protocolo inseguro ativo, certificado expirando em ≤ 30 dias |
| `ALTO` | Cipher fraco, chave pequena, renegociação habilitada, cert ≤ 90 dias |
| `MEDIO` | Protocolos não bloqueados explicitamente, TLS 1.3 ausente |
| `INFO` | Informações complementares sem impacto direto |
| `OK` | Configuração em conformidade |

---

## Pré-requisitos

- Python 3.8+
- Acesso à API REST do F5 BIG-IP (porta 443)
- Usuário com permissão de leitura na partição desejada

```bash
pip install requests urllib3 jinja2
```

---

## Uso

### Fase Pré-validação

Coleta o estado atual, analisa e salva o baseline JSON para comparação futura.

```bash
python f5_tls_validator.py \
  --host 192.168.1.1 \
  --user admin \
  --password MinhaSenh@123 \
  --phase pre
```

Arquivos gerados:
- `f5_tls_report_pre_<timestamp>.html` — relatório HTML
- `f5_tls_baseline.json` — baseline para comparação

### Fase Pós-validação

Coleta o estado atual, compara com o baseline e exibe o delta no relatório.

```bash
python f5_tls_validator.py \
  --host 192.168.1.1 \
  --user admin \
  --password MinhaSenh@123 \
  --phase post \
  --baseline f5_tls_baseline.json
```

### Parâmetros disponíveis

| Parâmetro | Obrigatório | Padrão | Descrição |
|---|---|---|---|
| `--host` | Sim | — | IP ou hostname do BIG-IP |
| `--user` | Sim | — | Usuário de administração |
| `--password` | Sim | — | Senha |
| `--port` | Não | `443` | Porta HTTPS da API |
| `--partition` | Não | `Common` | Partição do BIG-IP |
| `--phase` | Não | `pre` | Fase: `pre` ou `post` |
| `--baseline` | Não | `f5_tls_baseline.json` | Arquivo de baseline para comparação |
| `--output` | Não | auto | Caminho do relatório HTML de saída |

---

## Relatório HTML

O relatório gerado contém:

- **Resumo executivo** com contagem de findings por severidade
- **Tabela de perfis SSL** com análise detalhada por categoria
- **Tabela de Virtual Servers** com profiles associados
- **Comparativo Pré vs Pós** (apenas na fase `post`) destacando o que foi adicionado, removido ou alterado

---

## Estrutura do Projeto

```
f5-bigip-tls-validator/
├── f5_tls_validator.py   # Script principal
├── README.md             # Documentação
└── f5_tls_baseline.json  # Gerado automaticamente na fase pré (não versionar com dados reais)
```

---

## Boas Práticas de Segurança

> Este script **não armazena credenciais**. O token de autenticação iControl é gerado por sessão e descartado ao término da execução.

Recomendações:
- Nunca versione o arquivo `f5_tls_baseline.json` se ele contiver dados sensíveis de produção
- Use usuários com permissão mínima necessária (somente leitura é suficiente)
- Execute em ambiente seguro com acesso controlado ao BIG-IP

---

## Referências

- [F5 iControl REST API Guide](https://clouddocs.f5.com/api/icontrol-rest/)
- [NIST SP 800-52 Rev. 2 — TLS Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [F5 Security Advisory — TLS Best Practices](https://support.f5.com/csp/article/K13171)
- [RFC 5746 — TLS Renegotiation](https://datatracker.ietf.org/doc/html/rfc5746)

---

## Licença

MIT License — sinta-se à vontade para adaptar ao seu ambiente.
