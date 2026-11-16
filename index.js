const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const arquivo = path.join(__dirname, 'data', 'empresas.json');

app.use(express.json({limit:'20kb'}));
app.use(express.static('public'));

function carregar() {
  if (!fs.existsSync(arquivo)) return [];
  return JSON.parse(fs.readFileSync(arquivo, 'utf8'));
}

app.get('/api/status', (req,res) => {
  res.json({
    empresa:'NEXORA',
    nome:'Carbon & Climate Solutions',
    status:'operacional',
    versao:'1.0.0'
  });
});

app.post('/api/empresas', (req,res) => {
  const {razaoSocial,cnpj,email,setor,senha} = req.body;

  if (!razaoSocial || !cnpj || !email || !setor || !senha)
    return res.status(400).json({erro:'Preencha todos os campos.'});

  const documento = String(cnpj).replace(/\D/g,'');
  const correio = String(email).trim().toLowerCase();

  if (documento.length !== 14)
    return res.status(400).json({erro:'CNPJ deve conter 14 números.'});

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correio))
    return res.status(400).json({erro:'E-mail inválido.'});

  if (String(senha).length < 10)
    return res.status(400).json({erro:'A senha deve ter pelo menos 10 caracteres.'});

  const empresas = carregar();

  if (empresas.some(e => e.cnpj === documento || e.email === correio))
    return res.status(409).json({erro:'CNPJ ou e-mail já cadastrado.'});

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(senha,salt,64).toString('hex');

  const empresa = {
    id:crypto.randomUUID(),
    razaoSocial:String(razaoSocial).trim(),
    cnpj:documento,
    email:correio,
    setor:String(setor).trim(),
    salt,
    passwordHash:hash,
    criadaEm:new Date().toISOString()
  };

  empresas.push(empresa);
  fs.writeFileSync(arquivo,JSON.stringify(empresas,null,2),{mode:0o600});
  fs.chmodSync(arquivo,0o600);

  res.status(201).json({
    sucesso:true,
    mensagem:'Cadastro empresarial recebido.',
    empresa:{
      id:empresa.id,
      razaoSocial:empresa.razaoSocial,
      email:empresa.email
    }
  });
});


// NEXORA_ADMIN_ROUTES
const diagnosticosArquivo = path.join(__dirname, 'data', 'diagnosticos.json');

function lerDiagnosticos() {
  if (!fs.existsSync(diagnosticosArquivo)) return [];
  return JSON.parse(fs.readFileSync(diagnosticosArquivo, 'utf8'));
}

function salvarDiagnosticos(dados) {
  fs.writeFileSync(diagnosticosArquivo, JSON.stringify(dados, null, 2), {mode: 0o600});
  fs.chmodSync(diagnosticosArquivo, 0o600);
}

function adminAuth(req, res, next) {
  const usuario = process.env.NEXORA_ADMIN_USER;
  const senha = process.env.NEXORA_ADMIN_PASS;

  if (!usuario || !senha || senha.length < 16)
    return res.status(503).json({erro: 'Acesso administrativo ainda não configurado.'});

  const cab = req.headers.authorization || '';
  let recebido = '';
  try {
    if (cab.startsWith('Basic '))
      recebido = Buffer.from(cab.slice(6), 'base64').toString('utf8');
  } catch (_) {}

  const pos = recebido.indexOf(':');
  const u = pos >= 0 ? recebido.slice(0, pos) : '';
  const p = pos >= 0 ? recebido.slice(pos + 1) : '';

  function igual(a, b) {
    const x = Buffer.from(a);
    const y = Buffer.from(b);
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  }

  if (!igual(u, usuario) || !igual(p, senha)) {
    res.setHeader('WWW-Authenticate', 'Basic realm="NEXORA Administracao"');
    return res.status(401).json({erro: 'Acesso não autorizado.'});
  }
  next();
}

app.use('/api/admin', adminAuth);

app.get('/api/admin/empresas', (req, res) => {
  const diagnosticos = lerDiagnosticos();
  const lista = carregar().map(e => {
    const d = diagnosticos.find(x => x.empresaId === e.id);
    return {
      id: e.id,
      razaoSocial: e.razaoSocial,
      cnpj: e.cnpj,
      email: e.email,
      setor: e.setor,
      criadaEm: e.criadaEm,
      diagnostico: d ? {
        escopo1: d.escopo1,
        escopo2: d.escopo2,
        escopo3: d.escopo3,
        status: d.status,
        atualizadoEm: d.atualizadoEm
      } : null
    };
  });
  res.json({total: lista.length, empresas: lista});
});

app.get('/api/admin/empresas/:id', (req, res) => {
  const empresa = carregar().find(e => e.id === req.params.id);
  if (!empresa) return res.status(404).json({erro: 'Empresa não encontrada.'});

  const diagnostico = lerDiagnosticos().find(x => x.empresaId === empresa.id) || null;

  res.json({
    empresa: {
      id: empresa.id,
      razaoSocial: empresa.razaoSocial,
      cnpj: empresa.cnpj,
      email: empresa.email,
      setor: empresa.setor,
      criadaEm: empresa.criadaEm
    },
    diagnostico
  });
});

app.post('/api/admin/empresas/:id/diagnostico', (req, res) => {
  const empresa = carregar().find(e => e.id === req.params.id);
  if (!empresa) return res.status(404).json({erro: 'Empresa não encontrada.'});

  const dados = lerDiagnosticos();
  const diagnostico = {
    empresaId: empresa.id,
    escopo1: String(req.body.escopo1 || '').slice(0, 3000),
    escopo2: String(req.body.escopo2 || '').slice(0, 3000),
    escopo3: String(req.body.escopo3 || '').slice(0, 3000),
    observacoes: String(req.body.observacoes || '').slice(0, 3000),
    status: 'em preenchimento',
    atualizadoEm: new Date().toISOString()
  };

  const indice = dados.findIndex(x => x.empresaId === empresa.id);
  if (indice >= 0) dados[indice] = diagnostico;
  else dados.push(diagnostico);

  salvarDiagnosticos(dados);
  res.json({sucesso: true, mensagem: 'Diagnóstico salvo.', diagnostico});
});
// FIM NEXORA_ADMIN_ROUTES


app.listen(process.env.PORT || 3000,'0.0.0.0',() => {
  console.log('NEXORA funcionando na porta ' + (process.env.PORT || 3000));
});
