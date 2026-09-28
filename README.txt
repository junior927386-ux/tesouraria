TESOURARIA DHG — INSTALAÇÃO

Windows (jeito fácil): instale o Node.js LTS (22 ou 24) e dê dois cliques em iniciar.bat.
Ele instala tudo, cria o .env e abre o navegador. A chave de sessão é gerada sozinha e guardada no banco.

Se a pasta node_modules ficou pela metade de uma tentativa que falhou, apague-a antes.
Manual: npm install > copie .env.example para .env > npm start > http://localhost:8000

COMO APP:
- No PC: abra http://localhost:8000 no Chrome ou Edge e clique no ícone "Instalar" na barra de endereço.
  O Tesouraria DHG passa a abrir em janela própria, com ícone.
- No celular (mesma rede): abra http://SEU-IP:8000 (IP via ipconfig).
  Obs.: a instalação completa como app exige HTTPS; por IP local, o navegador só cria um atalho.
  Para instalar de verdade no celular, publique o servidor com HTTPS (ex.: Render, Railway ou um túnel).

LOGIN: Gmail (@gmail.com) + senha de no mínimo 8 caracteres (guardada com hash). Login Google opcional via GOOGLE_CLIENT_ID/SECRET.
SAÍDA: exige nome e diretoria/cargo; gera recibo com código, para imprimir ou salvar em PDF.
BANCO: caixa-azul.db (nome mantido para não perder seus dados; faça backup). Sessões também ficam nele, então o login continua após reiniciar.
GOOGLE OAUTH: cadastre http://localhost:8000/auth/google/callback no Google Cloud e ajuste GOOGLE_CALLBACK_URL.

ADMINISTRADOR:
Se ainda não existir admin, a conta mais antiga vira admin automaticamente. Para promover outras, coloque no .env:
ADMIN_EMAILS=email1@gmail.com,email2@gmail.com
O admin ganha o botão Admin: vê todos os usuários e movimentações, troca senhas, promove/remove admins e exclui usuários.

USAR EM OUTRO APARELHO COM OS MESMOS DADOS:
Os dados ficam no computador que roda o servidor (caixa-azul.db). Qualquer aparelho que abrir o servidor vê os mesmos dados.
1) Mesma rede Wi-Fi: com o iniciar.bat aberto, a janela mostra "Em outro aparelho: http://192.168.x.x:8000". Abra esse endereço no celular.
   Na primeira vez o Windows pergunta sobre o Firewall: permita em "Redes privadas". O computador precisa ficar ligado.
2) De qualquer lugar: publique em um serviço com HTTPS que aceite Docker (há Dockerfile pronto) e com disco persistente.
   Defina DB_PATH apontando para o disco (ex.: /data/caixa-azul.db). Sem disco persistente os dados somem a cada atualização.
   Para levar os dados atuais, copie o caixa-azul.db para esse disco. Com HTTPS o celular instala como app de verdade.
