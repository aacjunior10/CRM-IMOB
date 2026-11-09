# Casa Norte CRM

CRM imobiliário com login individual, sessões simultâneas e administração de contas. O cadastro aceita 15 ou mais usuários; não há limite configurado.

## Requisitos

- Python 3.10 ou mais recente
- Para o servidor local com SQLite, nenhuma biblioteca externa
- Para o aplicativo ASGI e PostgreSQL na Vercel, `pip install -r requirements.txt`

## Primeiro acesso

No terminal do VS Code, na pasta do projeto, crie a primeira conta administradora:

```powershell
python manage_users.py create --name "Marina Costa" --username marina --role admin
```

Digite e confirme uma senha com pelo menos 12 caracteres quando solicitado. A senha não aparece no terminal nem fica no código.

Inicie o servidor para aceitar acesso remoto na rede local:

```powershell
$env:CRM_HOST = "0.0.0.0"
python server.py
```

Abra `http://127.0.0.1:8000` no próprio computador ou `http://SEU_IP_DA_REDE:8000` em outros dispositivos da mesma rede, entre com a conta criada e use **Acessos da equipe** para cadastrar as demais pessoas. As contas são independentes e o servidor aceita sessões concorrentes.


Na tela de login, o link **Criar cadastro de acesso** permite que corretores enviem uma solicitação de conta. Esses cadastros recebem sempre o perfil **Equipe**, ficam pendentes e só podem entrar após aprovação de um administrador. Contas criadas diretamente na área administrativa já ficam aprovadas.

No cadastro do corretor, o e-mail é obrigatório e a foto de perfil é opcional. São aceitas imagens PNG, JPEG ou WebP de até 512 KB; o e-mail aparece na lista de acessos administrativos.

Na tela de login, use **Mostrar** para conferir a senha digitada. Se alguém esquecer a senha, deve solicitar a redefinição ao administrador, que pode usar **Redefinir senha** em **Acessos da equipe**. A nova senha deve ter pelo menos 12 caracteres e a alteração encerra as sessões anteriores da conta. Se o administrador precisar redefinir a própria senha, outro administrador pode fazê-lo; alternativamente, use `python manage_users.py reset-password --username SEU_USUARIO` no terminal do servidor.

## Operação

```powershell
python manage_users.py list
python manage_users.py create --name "Nome da pessoa" --username pessoa
python manage_users.py disable --username pessoa
python manage_users.py enable --username pessoa
python manage_users.py reset-password --username pessoa
python manage_users.py set-role --username pessoa --role admin
```

Os usuários, sessões e leads compartilhadas ficam no arquivo `casa_norte.sqlite3`. Senhas são derivadas com PBKDF2-HMAC-SHA256; o servidor armazena somente hashes com salt. Após cinco tentativas incorretas para o mesmo usuário e endereço, o login é bloqueado por 15 minutos. Desativar uma conta encerra suas sessões.

## Acesso pela equipe

Para acesso por outros computadores da rede local, use `CRM_HOST=0.0.0.0`. Para acesso externo não exponha diretamente a internet: configure um proxy reverso com HTTPS, restrinja o acesso à rede da empresa, defina `CRM_TRUST_PROXY=1` e `CRM_HTTPS=1`, e encaminhe o tráfego ao servidor local. HTTPS é obrigatório fora do próprio computador para proteger senhas e cookies de sessão.

É possível definir `CRM_PORT` e `CRM_DATABASE` para personalizar a porta e o arquivo de dados. As sessões usam tokens aleatórios criptograficamente seguros, armazenados no banco somente como hashes.

## Publicação na Vercel

O projeto também expõe as páginas e rotas da API pelo aplicativo ASGI em `app.py`. Na Vercel, vincule um banco PostgreSQL gerenciado (por exemplo, Neon) e configure a variável `DATABASE_URL` com a URL de conexão **pooled** do banco. Não salve essa URL nos arquivos do projeto. A Vercel deve detectar o aplicativo Python por `app.py` e `requirements.txt`; faça um novo deploy depois de configurar a variável. Sem uma URL PostgreSQL, o aplicativo na Vercel falha explicitamente em vez de gravar dados em um disco temporário.

Crie/vincule o banco PostgreSQL antes do primeiro deploy. Cadastre `DATABASE_URL` no painel da Vercel para produção (e preview, se usado) e mantenha essa variável também no terminal apenas durante a migração. Não envie a URL de conexão pelo chat nem a inclua no repositório.

Para copiar os dados atuais do SQLite, configure `DATABASE_URL` temporariamente no terminal local com a mesma URL segura do banco e execute:

```powershell
python migrate_sqlite_to_postgres.py
```

O script copia contas, sessões, tentativas de login, leads e documentos para um PostgreSQL vazio e mantém o arquivo SQLite original. Se encontrar dados existentes nas tabelas do CRM, ele interrompe a operação em vez de mesclar contas ou sobrescrever dados. Faça a migração uma vez e confira os totais. Se o banco migrado não tiver administrador, crie a conta usando a mesma `DATABASE_URL`:

```powershell
python manage_users.py create --name "Nome do administrador" --username admin --role admin
```

Para operar localmente com PostgreSQL, defina `DATABASE_URL`; sem ela, o servidor e os comandos administrativos continuam usando SQLite. No projeto Vercel, configure `DATABASE_URL` nos ambientes de produção e preview, conforme necessário, e nunca inclua credenciais em commits.
