const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const winston = require('winston');
const os = require('os');
const crypto = require('crypto');
require('dotenv').config();
const path = require('path');

// Função para detectar o IP local
function getLocalIPAddress() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1'; // fallback
}

const app = express();
const port = process.env.PORT || 3000;
const ip = '0.0.0.0'; // Ouvir em todas as interfaces

// Configurar logger com winston
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/server.log' }),
    new winston.transports.Console()
  ],
});

// Middleware CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*'); // Ajustar para produção
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).json({});
  logger.info(`Requisição recebida: ${req.method} ${req.url} from ${req.ip}`);
  next();
});

app.use(bodyParser.json());

// Configurar EJS e arquivos estáticos
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware de autenticação
const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logger.warn(`Tentativa de acesso sem token: ${req.ip}`);
    return res.status(401).json({ error: 'Token de autenticação não fornecido' });
  }
  if (token !== process.env.AUTH_TOKEN) {
    logger.warn(`Token inválido: ${req.ip}`);
    return res.status(403).json({ error: 'Token inválido' });
  }
  next();
};

// Conexão com MongoDB
mongoose.connect('mongodb://localhost:27017/mdm', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  retryWrites: true,
  maxPoolSize: 10,
}).then(() => {
  logger.info('Conectado ao MongoDB');
}).catch((err) => {
  logger.error(`Erro ao conectar ao MongoDB: ${err.message}`);
  process.exit(1);
});

mongoose.connection.on('disconnected', () => {
  logger.warn('Desconectado do MongoDB, tentando reconectar...');
});

// Modelo de dispositivo
const DeviceSchema = new mongoose.Schema({
  device_name: { type: String, required: true },
  device_model: { type: String },
  device_id: { type: String, unique: true, required: true },
  battery: { type: Number },
  network: { type: String },
  host: { type: String },
  serial_number: { type: String },
  imei: { type: String },
  sector: { type: String },
  floor: { type: String },
  last_sync: { type: String },
  secure_android_id: { type: String },
  mac_address: { type: String },
  ip_address: { type: String },
  last_seen: { type: Date, default: Date.now },
  maintenance_status: { type: Boolean, default: false },
  maintenance_ticket: { type: String },
  maintenance_history: [{
    timestamp: { type: Date, required: true },
    status: { type: String, required: true },
    ticket: { type: String }
  }],
  unit: { type: String },
  // Campos de provisionamento
  provisioning_status: { 
    type: String, 
    enum: ['pending', 'in_progress', 'completed', 'failed'], 
    default: 'pending' 
  },
  provisioning_token: { type: String },
  enrollment_date: { type: Date, default: Date.now },
  configuration_profile: { type: String },
  owner_organization: { type: String },
  compliance_status: { 
    type: String, 
    enum: ['compliant', 'non_compliant', 'unknown'], 
    default: 'unknown' 
  },
  installed_apps: [{ 
    package_name: String,
    version: String,
    install_date: Date
  }],
  security_policies: {
    password_required: { type: Boolean, default: false },
    encryption_enabled: { type: Boolean, default: false },
    screen_lock_timeout: { type: Number, default: 0 },
    allow_unknown_sources: { type: Boolean, default: false }
  }
});

const Device = mongoose.model('Device', DeviceSchema);

// Modelo de comando
const CommandSchema = new mongoose.Schema({
  device_id: { type: String, required: true },
  command: { type: String, required: true },
  parameters: { type: Object },
  status: { type: String, default: 'pending' },
  result: { type: String },
  createdAt: { type: Date, default: Date.now },
  executedAt: { type: Date }
});

const Command = mongoose.model('Command', CommandSchema);

// Modelo de perfil de configuração
const ConfigProfileSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String },
  settings: {
    wifi_configs: [{
      ssid: String,
      password: String,
      security_type: String
    }],
    app_whitelist: [String],
    app_blacklist: [String],
    restrictions: {
      disable_camera: { type: Boolean, default: false },
      disable_bluetooth: { type: Boolean, default: false },
      disable_usb: { type: Boolean, default: false },
      disable_developer_options: { type: Boolean, default: true }
    },
    mandatory_apps: [{
      package_name: String,
      apk_url: String,
      version: String
    }]
  },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

const ConfigProfile = mongoose.model('ConfigProfile', ConfigProfileSchema);

// Modelo de token de provisionamento
const ProvisioningTokenSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  organization: { type: String, required: true },
  config_profile: { type: String, required: true },
  max_uses: { type: Number, default: 1 },
  used_count: { type: Number, default: 0 },
  expires_at: { type: Date, required: true },
  created_at: { type: Date, default: Date.now },
  is_active: { type: Boolean, default: true }
});

const ProvisioningToken = mongoose.model('ProvisioningToken', ProvisioningTokenSchema);

// === ROTAS DE PROVISIONAMENTO ===

// Gerar token de provisionamento
app.post('/api/provisioning/generate-token', authenticate, async (req, res) => {
  try {
    const { organization, config_profile, max_uses = 1, expires_in_hours = 24 } = req.body;
    
    if (!organization || !config_profile) {
      return res.status(400).json({ error: 'organization e config_profile são obrigatórios' });
    }

    // Verificar se o perfil existe
    const profile = await ConfigProfile.findOne({ name: config_profile });
    if (!profile) {
      return res.status(404).json({ error: 'Perfil de configuração não encontrado' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expires_at = new Date(Date.now() + expires_in_hours * 60 * 60 * 1000);

    const provisioningToken = new ProvisioningToken({
      token,
      organization,
      config_profile,
      max_uses,
      expires_at
    });

    await provisioningToken.save();
    
    logger.info(`Token de provisionamento gerado: ${token} para ${organization}`);
    res.status(201).json({
      token,
      organization,
      config_profile,
      max_uses,
      expires_at,
      provisioning_url: `http://${getLocalIPAddress()}:${port}/provision/${token}`
    });
  } catch (err) {
    logger.error(`Erro ao gerar token de provisionamento: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Endpoint de provisionamento (usado pelo dispositivo)
app.post('/api/provisioning/enroll', async (req, res) => {
  try {
    const { 
      provisioning_token, 
      device_id, 
      device_name, 
      device_model,
      serial_number,
      imei,
      secure_android_id,
      mac_address,
      ip_address 
    } = req.body;

    if (!provisioning_token || !device_id || !device_name) {
      return res.status(400).json({ error: 'provisioning_token, device_id e device_name são obrigatórios' });
    }

    // Verificar token
    const token = await ProvisioningToken.findOne({ 
      token: provisioning_token,
      is_active: true,
      expires_at: { $gt: new Date() }
    });

    if (!token) {
      logger.warn(`Token de provisionamento inválido ou expirado: ${provisioning_token}`);
      return res.status(401).json({ error: 'Token de provisionamento inválido ou expirado' });
    }

    if (token.used_count >= token.max_uses) {
      logger.warn(`Token de provisionamento esgotado: ${provisioning_token}`);
      return res.status(401).json({ error: 'Token de provisionamento esgotado' });
    }

    // Verificar se dispositivo já existe
    let device = await Device.findOne({ device_id });
    
    if (device && device.provisioning_status === 'completed') {
      return res.status(409).json({ error: 'Dispositivo já provisionado' });
    }

    // Buscar perfil de configuração
    const configProfile = await ConfigProfile.findOne({ name: token.config_profile });
    if (!configProfile) {
      return res.status(500).json({ error: 'Perfil de configuração não encontrado' });
    }

    // Criar ou atualizar dispositivo
    const deviceData = {
      device_name,
      device_model,
      device_id,
      serial_number,
      imei,
      secure_android_id,
      mac_address,
      ip_address,
      provisioning_status: 'in_progress',
      provisioning_token,
      configuration_profile: token.config_profile,
      owner_organization: token.organization,
      enrollment_date: new Date(),
      last_seen: new Date()
    };

    if (device) {
      Object.assign(device, deviceData);
    } else {
      device = new Device(deviceData);
    }

    await device.save();

    // Atualizar contador do token
    token.used_count += 1;
    await token.save();

    // Criar comandos de configuração inicial
    const initialCommands = [];

    // Instalar apps obrigatórios
    if (configProfile.settings.mandatory_apps) {
      for (const app of configProfile.settings.mandatory_apps) {
        initialCommands.push({
          device_id,
          command: 'install_app',
          parameters: {
            package_name: app.package_name,
            apk_url: app.apk_url,
            version: app.version
          }
        });
      }
    }

    // Aplicar restrições
    if (configProfile.settings.restrictions) {
      initialCommands.push({
        device_id,
        command: 'apply_restrictions',
        parameters: configProfile.settings.restrictions
      });
    }

    // Configurar WiFi
    if (configProfile.settings.wifi_configs && configProfile.settings.wifi_configs.length > 0) {
      initialCommands.push({
        device_id,
        command: 'configure_wifi',
        parameters: { wifi_configs: configProfile.settings.wifi_configs }
      });
    }

    // Salvar comandos
    if (initialCommands.length > 0) {
      await Command.insertMany(initialCommands);
    }

    logger.info(`Dispositivo provisionado: ${device_id} para ${token.organization}`);
    
    res.status(200).json({
      message: 'Dispositivo provisionado com sucesso',
      device_id,
      organization: token.organization,
      config_profile: token.config_profile,
      commands_count: initialCommands.length
    });

  } catch (err) {
    logger.error(`Erro no provisionamento: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Finalizar provisionamento
app.post('/api/provisioning/complete', authenticate, async (req, res) => {
  try {
    const { device_id, success, error_message } = req.body;

    if (!device_id) {
      return res.status(400).json({ error: 'device_id é obrigatório' });
    }

    const device = await Device.findOne({ device_id });
    if (!device) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }

    device.provisioning_status = success ? 'completed' : 'failed';
    if (!success && error_message) {
      device.provisioning_error = error_message;
    }
    device.compliance_status = success ? 'compliant' : 'non_compliant';

    await device.save();

    logger.info(`Provisionamento ${success ? 'concluído' : 'falhou'} para: ${device_id}`);
    res.status(200).json({ message: 'Status de provisionamento atualizado' });

  } catch (err) {
    logger.error(`Erro ao finalizar provisionamento: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// === ROTAS DE PERFIS DE CONFIGURAÇÃO ===

// Criar perfil de configuração
app.post('/api/config-profiles', authenticate, async (req, res) => {
  try {
    const profileData = req.body;
    
    if (!profileData.name) {
      return res.status(400).json({ error: 'Nome do perfil é obrigatório' });
    }

    const profile = new ConfigProfile(profileData);
    await profile.save();

    logger.info(`Perfil de configuração criado: ${profileData.name}`);
    res.status(201).json(profile);

  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Perfil com este nome já existe' });
    }
    logger.error(`Erro ao criar perfil: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Listar perfis de configuração
app.get('/api/config-profiles', authenticate, async (req, res) => {
  try {
    const profiles = await ConfigProfile.find().lean();
    res.status(200).json(profiles);
  } catch (err) {
    logger.error(`Erro ao listar perfis: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// === ROTAS EXISTENTES (CORRIGIDAS) ===

// Receber e salvar dados do dispositivo
app.post('/api/devices/data', authenticate, async (req, res) => {
  try {
    const data = req.body;
    logger.info(`Dados recebidos de ${req.ip}: ${JSON.stringify(data)}`);
    
    if (!data.device_id || !data.device_name) {
      logger.warn(`Faltam campos obrigatórios: device_id ou device_name de ${req.ip}`);
      return res.status(400).json({ error: 'device_id e device_name são obrigatórios' });
    }

    let device = await Device.findOne({ device_id: data.device_id });

    if (device) {
      Object.assign(device, data, { last_seen: new Date() });
      logger.info(`Dispositivo atualizado: ${data.device_id}`);
    } else {
      device = new Device({ ...data, last_seen: new Date() });
      logger.info(`Novo dispositivo criado: ${data.device_id}`);
    }

    await device.save();
    res.status(200).json({ message: 'Dados salvos com sucesso' });
  } catch (err) {
    logger.error(`Erro ao salvar dados de ${req.ip}: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor', details: err.message });
  }
});

// Heartbeat para atualizar last_seen
app.post('/api/devices/heartbeat', authenticate, async (req, res) => {
  try {
    const { device_id } = req.body;
    if (!device_id) {
      logger.warn(`Falta campo obrigatório: device_id de ${req.ip}`);
      return res.status(400).json({ error: 'device_id é obrigatório' });
    }

    const device = await Device.findOneAndUpdate(
      { device_id },
      { last_seen: new Date() },
      { new: true }
    );

    if (!device) {
      logger.warn(`Dispositivo não encontrado para heartbeat: ${device_id}`);
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }

    logger.info(`Heartbeat recebido de: ${device_id}`);
    res.status(200).json({ message: 'Heartbeat registrado com sucesso' });
  } catch (err) {
    logger.error(`Erro no heartbeat de ${req.ip}: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Listar dispositivos
app.get('/api/devices', authenticate, async (req, res) => {
  try {
    const devices = await Device.find().lean();
    logger.info(`Lista de dispositivos retornada: ${devices.length} dispositivos`);
    res.status(200).json(devices);
  } catch (err) {
    logger.error(`Erro ao obter dispositivos: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Obter comandos pendentes
app.get('/api/devices/commands', authenticate, async (req, res) => {
  try {
    const device_id = req.query.device_id;
    if (!device_id) {
      logger.warn('Falta campo obrigatório: device_id');
      return res.status(400).json({ error: 'device_id é obrigatório' });
    }

    const commands = await Command.find({ device_id, status: 'pending' }).lean();
    if (commands.length > 0) {
      await Command.updateMany({ device_id, status: 'pending' }, { status: 'sent' });
      logger.info(`Comandos pendentes encontrados para ${device_id}: ${commands.length}`);
    }

    res.status(200).json(commands.map(cmd => ({
      id: cmd._id.toString(),
      command_type: cmd.command,
      parameters: cmd.parameters
    })));
  } catch (err) {
    logger.error(`Erro ao obter comandos: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Executar comando
app.post('/api/executeCommand', authenticate, async (req, res) => {
  const { device_id, command, packageName, apkUrl, maintenance_status, maintenance_ticket, maintenance_history_entry } = req.body;

  try {
    if (!device_id || !command) {
      logger.warn('Faltam campos obrigatórios: device_id ou command');
      return res.status(400).json({ error: 'device_id e command são obrigatórios' });
    }

    if (command === 'set_maintenance') {
      if (typeof maintenance_status !== 'boolean') {
        logger.warn(`maintenance_status deve ser booleano para ${device_id}`);
        return res.status(400).json({ error: 'maintenance_status deve ser um valor booleano' });
      }

      const updateFields = {
        maintenance_status,
        maintenance_ticket: maintenance_ticket || '',
      };

      if (maintenance_history_entry) {
        try {
          const historyEntry = JSON.parse(maintenance_history_entry);
          if (!historyEntry.timestamp || !historyEntry.status) {
            logger.warn(`maintenance_history_entry inválido para ${device_id}`);
            return res.status(400).json({ error: 'maintenance_history_entry deve conter timestamp e status' });
          }
          updateFields.$push = { maintenance_history: historyEntry };
        } catch (err) {
          logger.error(`Erro ao parsear maintenance_history_entry para ${device_id}: ${err.message}`);
          return res.status(400).json({ error: 'Formato inválido para maintenance_history_entry' });
        }
      }

      const device = await Device.findOneAndUpdate(
        { device_id },
        updateFields,
        { new: true }
      );

      if (!device) {
        logger.warn(`Dispositivo não encontrado: ${device_id}`);
        return res.status(404).json({ error: 'Dispositivo não encontrado' });
      }

      logger.info(`Comando set_maintenance executado para ${device_id}: status=${maintenance_status}`);
      return res.status(200).json({ message: `Status de manutenção atualizado para ${device_id}` });
    } else {
      // Outros comandos (lock, uninstall, install)
      await Command.create({ 
        device_id, 
        command, 
        parameters: { packageName, apkUrl }
      });
      logger.info(`Comando "${command}" registrado para ${device_id}`);
      res.status(200).json({ message: `Comando ${command} registrado com sucesso` });
    }
  } catch (err) {
    logger.error(`Erro ao processar comando: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Reportar resultado de comando
app.post('/api/devices/command-result', authenticate, async (req, res) => {
  try {
    const { command_id, device_id, success, result, error_message } = req.body;

    if (!command_id && !device_id) {
      return res.status(400).json({ error: 'command_id ou device_id é obrigatório' });
    }

    const updateData = {
      status: success ? 'completed' : 'failed',
      result: result || error_message,
      executedAt: new Date()
    };

    let command;
    if (command_id) {
      command = await Command.findByIdAndUpdate(command_id, updateData, { new: true });
    } else {
      command = await Command.findOneAndUpdate(
        { device_id, status: 'sent' },
        updateData,
        { new: true, sort: { createdAt: -1 } }
      );
    }

    if (!command) {
      return res.status(404).json({ error: 'Comando não encontrado' });
    }

    logger.info(`Resultado do comando recebido: ${command.command} para ${device_id} - ${success ? 'sucesso' : 'falha'}`);
    res.status(200).json({ message: 'Resultado do comando registrado' });

  } catch (err) {
    logger.error(`Erro ao registrar resultado do comando: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Métricas do servidor
app.get('/api/server/status', authenticate, async (req, res) => {
  try {
    const cpus = os.cpus();
    const totalIdle = cpus.reduce((sum, cpu) => sum + cpu.times.idle, 0);
    const totalTick = cpus.reduce((sum, cpu) => sum + Object.values(cpu.times).reduce((t, v) => t + v, 0), 0);
    const cpuUsage = totalTick ? ((1 - totalIdle / totalTick) * 100).toFixed(2) : 0;

    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    const memoryUsage = ((1 - freeMemory / totalMemory) * 100).toFixed(2);

    const metrics = {
      cpu_usage: parseFloat(cpuUsage),
      memory_usage: parseFloat(memoryUsage),
      uptime: os.uptime(),
      device_count: await Device.countDocuments(),
      provisioned_devices: await Device.countDocuments({ provisioning_status: 'completed' }),
      pending_commands: await Command.countDocuments({ status: 'pending' })
    };

    logger.info(`Métricas do servidor retornadas: CPU ${metrics.cpu_usage}%, Memória ${metrics.memory_usage}%`);
    res.status(200).json(metrics);
  } catch (err) {
    logger.error(`Erro ao obter métricas do servidor: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para o painel web
app.get('/', (req, res) => {
  res.render('index', { token: process.env.AUTH_TOKEN });
});

// Rota de provisionamento via web
app.get('/provision/:token', async (req, res) => {
  try {
    const token = await ProvisioningToken.findOne({ 
      token: req.params.token,
      is_active: true,
      expires_at: { $gt: new Date() }
    });

    if (!token) {
      return res.status(404).send('Token de provisionamento inválido ou expirado');
    }

    res.render('provision', { 
      token: req.params.token,
      organization: token.organization,
      server_url: `http://${getLocalIPAddress()}:${port}`
    });
  } catch (err) {
    logger.error(`Erro na página de provisionamento: ${err.message}`);
    res.status(500).send('Erro interno do servidor');
  }
});

// Iniciar servidor
app.listen(port, ip, () => {
  logger.info(`🚀 MDM Server rodando em http://${getLocalIPAddress()}:${port}`);
  logger.info(`📱 Provisionamento disponível em: http://${getLocalIPAddress()}:${port}/provision/{token}`);
});