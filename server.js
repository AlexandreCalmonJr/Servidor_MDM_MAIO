const express = require('express');
const mongoose = require('mongoose');
const winston = require('winston');
const os = require('os');
const crypto = require('crypto');
require('dotenv').config();
const path = require('path');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { body, validationResult, query } = require('express-validator');
const fs = require('fs').promises;

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
  return '127.0.0.1';
}

const app = express();
const port = process.env.PORT || 3000;
const ip = '0.0.0.0';

// Configurar logger com winston
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({
      filename: 'logs/server.log',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
      tailable: true
    }),
    new winston.transports.Console()
  ],
});

// Middleware de compressão
app.use(compression());

// Middleware CORS
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  preflightContinue: false,
  optionsSuccessStatus: 200,
}));

// Middleware de rate limiting
const limiter = rateLimit({
  windowMs: 1* 60 * 1000, // 15 minutos
  max: 100, // Limite de 100 requisições por IP
  message: 'Muitas requisições a partir deste IP, tente novamente após 15 minutos.',
});
app.use(limiter);

// Middleware para provisionamento
const enrollLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // Limite de 10 requisições por IP
  message: 'Muitas tentativas de provisionamento, tente novamente após 15 minutos.',
});

// Middleware para parsing de JSON
app.use(express.json());

// Configurar EJS e arquivos estáticos
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));

// Middleware de log de requisições
app.use((req, res, next) => {
  logger.info(`Requisição recebida: ${req.method} ${req.url} from ${req.ip}`);
  next();
});

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

// Middleware global de tratamento de erros
app.use((err, req, res, next) => {
  logger.error(`Erro não tratado: ${err.message}`);
  res.status(500).json({ error: 'Erro interno do servidor', details: err.message });
});

// Conexão com MongoDB
mongoose.connect('mongodb://localhost:27017/mdm', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  retryWrites: true,
  maxPoolSize: 50,
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
  device_name: { type: String, required: true, trim: false }, // Desativar trim
  device_model: { type: String, trim: false, default: 'N/A' },
  device_id: { type: String, required: true, trim: false },
  serial_number: { type: String, unique: true, trim: false, sparse: true, default: 'N/A' },
  imei: { type: String, unique: true, trim: false, sparse: true, default: 'N/A' },
  battery: { type: Number, min: 0, max: 100, default: null },
  network: { type: String, trim: false, default: 'N/A' },
  host: { type: String, trim: false, default: 'N/A' },
  sector: { type: String, trim: false, default: 'Desconhecido' },
  floor: { type: String, trim: false, default: 'Desconhecido' },
  mac_address_radio: { type: String, trim: false, default: 'N/A' }, // Adicionado
  last_sync: { type: String, trim: false, default: 'N/A' },
  secure_android_id: { type: String, trim: false, default: 'N/A' },
  ip_address: { type: String, trim: false, default: 'N/A' },
  wifi_ipv6: { type: String, trim: false, default: 'N/A' },
  wifi_gateway_ip: { type: String, trim: false, default: 'N/A' },
  wifi_broadcast: { type: String, trim: false, default: 'N/A' },
  wifi_submask: { type: String, trim: false, default: 'N/A' },
  last_seen: { type: String, trim: false }, // Alterado para String para manter formato do cliente
  maintenance_status: { type: Boolean, default: false },
  maintenance_ticket: { type: String, default: '' },
  maintenance_history: [{
    timestamp: { type: Date, required: true },
    status: { type: String, required: true },
    ticket: { type: String }
  }],
  unit: { type: String, trim: false, default: 'N/A' },
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

// Validação para garantir imei ou serial_number
DeviceSchema.pre('validate', function (next) {
  if (!this.imei && !this.serial_number) {
    return next(new Error('Pelo menos um dos campos imei ou serial_number deve ser fornecido'));
  }
  next();
});

// Índices
DeviceSchema.index({ serial_number: 1 }, { unique: true, sparse: true });
DeviceSchema.index({ bssid: 1 });

const Device = mongoose.model('Device', DeviceSchema);

// Modelo de comando
const CommandSchema = new mongoose.Schema({
  device_name: { type: String, required: true, trim: true },
  serial_number: { type: String, required: true, trim: true },
  command: { type: String, required: true, trim: true },
  parameters: { type: Object },
  status: { type: String, default: 'pending' },
  result: { type: String },
  createdAt: { type: Date, default: Date.now },
  executedAt: { type: Date }
});

CommandSchema.index({ serial_number: 1, status: 1 });

const Command = mongoose.model('Command', CommandSchema);

// Modelo de perfil de configuração
const ConfigProfileSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true, trim: true },
  description: { type: String, trim: true },
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
  organization: { type: String, required: true, trim: true },
  config_profile: { type: String, required: true, trim: true },
  max_uses: { type: Number, default: 1 },
  used_count: { type: Number, default: 0 },
  expires_at: { type: Date, required: true },
  created_at: { type: Date, default: Date.now },
  is_active: { type: Boolean, default: true }
});

const ProvisioningToken = mongoose.model('ProvisioningToken', ProvisioningTokenSchema);

// Modelo de mapeamento de BSSID
const BssidMappingSchema = new mongoose.Schema({
  mac_address_radio: { type: String, required: true, unique: true, trim: false },
  sector: { type: String, required: true, trim: false },
  floor: { type: String, required: true, trim: false }
});

const BssidMapping = mongoose.model('BssidMapping', BssidMappingSchema);

// Função para mapear BSSID para setor e andar
async function mapMacAddressRadioToLocation(mac_address_radio) {
  if (!mac_address_radio || mac_address_radio === 'N/A') {
    return { sector: 'Desconhecido', floor: 'Desconhecido' };
  }
  const mapping = await BssidMapping.findOne({ bssid: mac_address_radio });
  return mapping ? { sector: mapping.sector, floor: mapping.floor } : { sector: 'Desconhecido', floor: 'Desconhecido' };
}

// === ROTAS ===

// Gerar token de provisionamento
app.post('/api/provisioning/generate-token', authenticate, async (req, res) => {
  try {
    const { organization, config_profile, max_uses = 1, expires_in_hours = 24 } = req.body;
    
    if (!organization || !config_profile) {
      return res.status(400).json({ error: 'organization e config_profile são obrigatórios' });
    }

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

// Endpoint de provisionamento
app.post('/api/provisioning/enroll', enrollLimiter, async (req, res) => {
  try {
    const { 
      provisioning_token, 
      device_id, 
      device_name, 
      device_model,
      serial_number,
      imei,
      secure_android_id,
      ip_address,
      bssid,
      wifi_ipv6,
      wifi_gateway_ip,
      wifi_broadcast,
      wifi_submask
    } = req.body;

    if (!provisioning_token || !device_id || !device_name) {
      return res.status(400).json({ error: 'provisioning_token, device_id e device_name são obrigatórios' });
    }

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

    let device = await Device.findOne({ serial_number });
    
    if (device && device.provisioning_status === 'completed') {
      return res.status(409).json({ error: 'Dispositivo já provisionado' });
    }

    const configProfile = await ConfigProfile.findOne({ name: token.config_profile });
    if (!configProfile) {
      return res.status(500).json({ error: 'Perfil de configuração não encontrado' });
    }

    async function mapMacAddressRadioToLocation(mac_address_radio) {
      if (!mac_address_radio || mac_address_radio === 'N/A') {
        return { sector: 'Desconhecido', floor: 'Desconhecido' };
      }
      const mapping = await BssidMapping.findOne({ bssid: mac_address_radio });
      return mapping ? { sector: mapping.sector, floor: mapping.floor } : { sector: 'Desconhecido', floor: 'Desconhecido' };
    }

    const deviceData = {
      device_name,
      device_model,
      serial_number,
      imei,
      secure_android_id,
      ip_address,
      bssid,
      wifi_ipv6,
      wifi_gateway_ip,
      wifi_broadcast,
      wifi_submask,
      sector: location.sector,
      floor: location.floor,
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

    token.used_count += 1;
    await token.save();

    const initialCommands = [];

    if (configProfile.settings.mandatory_apps) {
      for (const app of configProfile.settings.mandatory_apps) {
        initialCommands.push({
          device_name,
          serial_number,
          command: 'install_app',
          parameters: {
            package_name: app.package_name,
            apk_url: app.apk_url,
            version: app.version
          }
        });
      }
    }

    if (configProfile.settings.restrictions) {
      initialCommands.push({
        device_name,
        serial_number,
        command: 'apply_restrictions',
        parameters: configProfile.settings.restrictions
      });
    }

    if (configProfile.settings.wifi_configs && configProfile.settings.wifi_configs.length > 0) {
      initialCommands.push({
        device_name,
        serial_number,
        command: 'configure_wifi',
        parameters: { wifi_configs: configProfile.settings.wifi_configs }
      });
    }

    if (initialCommands.length > 0) {
      await Command.insertMany(initialCommands);
    }

    logger.info(`Dispositivo provisionado: ${serial_number} para ${token.organization}`);
    res.status(200).json({
      message: 'Dispositivo provisionado com sucesso',
      device_id,
      serial_number,
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
    const { device_id, serial_number, success, error_message } = req.body;

    if (!serial_number || !device_id) {
      return res.status(400).json({ error: 'serial_number e device_id são obrigatórios' });
    }

    const device = await Device.findOne({ serial_number });
    if (!device) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }

    device.provisioning_status = success ? 'completed' : 'failed';
    if (!success && error_message) {
      device.provisioning_error = error_message;
    }
    device.compliance_status = success ? 'compliant' : 'non_compliant';

    await device.save();

    logger.info(`Provisionamento ${success ? 'concluído' : 'falhou'} para: ${serial_number}`);
    res.status(200).json({ message: 'Status de provisionamento atualizado' });

  } catch (err) {
    logger.error(`Erro ao finalizar provisionamento: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

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

// Receber e salvar dados do dispositivo
app.post('/api/devices/data', authenticate, [
  body('device_id').notEmpty().withMessage('device_id é obrigatório'),
  body('device_name').notEmpty().withMessage('device_name é obrigatório'),
  body('serial_number').notEmpty().withMessage('serial_number é obrigatório'),
  body('battery').optional().isInt({ min: 0, max: 100 }).withMessage('battery deve ser um número entre 0 e 100'),
  body('ip_address').optional().isIP().withMessage('ip_address deve ser um IP válido'),
  body('mac_address_radio').optional().matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/).withMessage('mac_address_radio deve ser um MAC válido'),
  body('wifi_ipv6').optional(),
  body('wifi_gateway_ip').optional().isIP().withMessage('wifi_gateway_ip deve ser um IP válido'),
  body('wifi_broadcast').optional().isIP().withMessage('wifi_broadcast deve ser um IP válido'),
  body('wifi_submask').optional(),
  body('device_model').optional(),
  body('imei').optional(),
  body('secure_android_id').optional(),
  body('network').optional(),
  body('host').optional(),
  body('sector').optional(),
  body('floor').optional(),
  body('last_seen').optional(),
  body('last_sync').optional(),
  body().custom((value) => {
    if (!value.imei && !value.serial_number) {
      throw new Error('Pelo menos um dos campos imei ou serial_number deve ser fornecido');
    }
    return true;
  }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Erros de validação: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    let data = req.body;
    logger.info(`Dados recebidos de ${req.ip}: ${JSON.stringify(data)}`);

    // Usar os dados exatamente como recebidos
    const deviceData = {
      device_name: data.device_name || 'unknown',
      device_model: data.device_model || 'N/A',
      device_id: data.device_id || 'unknown',
      serial_number: data.serial_number || 'N/A',
      imei: data.imei || 'N/A',
      battery: data.battery != null ? data.battery : null,
      network: data.network || 'N/A',
      host: data.host || 'N/A',
      sector: data.sector || 'Desconhecido',
      floor: data.floor || 'Desconhecido',
      mac_address_radio: data.mac_address_radio || 'N/A',
      last_sync: data.last_sync || 'N/A',
      secure_android_id: data.secure_android_id || 'N/A',
      ip_address: data.ip_address || 'N/A',
      wifi_ipv6: data.wifi_ipv6 || 'N/A',
      wifi_gateway_ip: data.wifi_gateway_ip || 'N/A',
      wifi_broadcast: data.wifi_broadcast || 'N/A',
      wifi_submask: data.wifi_submask || 'N/A',
      last_seen: data.last_seen || new Date().toISOString(),
    };

    // Logar dados recebidos para depuração
    logger.debug(`Dados a serem salvos: ${JSON.stringify(deviceData)}`);

    const device = await Device.findOneAndUpdate(
      { serial_number: deviceData.serial_number },
      { $set: deviceData },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    logger.info(`Dispositivo ${device.serial_number} salvo/atualizado com sucesso`);
    res.status(200).json({ message: 'Dados salvos com sucesso', deviceId: device._id });
  } catch (err) {
    if (err.code === 11000) {
      const field = err.keyValue?.serial_number ? 'serial_number' : 'imei';
      const value = err.keyValue?.serial_number || err.keyValue?.imei;
      logger.error(`Erro de duplicidade para ${field}: ${value}`);
      return res.status(409).json({ error: `Dispositivo com este ${field} já existe`, field, value });
    }
    logger.error(`Erro ao salvar dados de ${req.ip}: ${err.message}`);
    return res.status(500).json({ error: 'Erro interno do servidor', details: err.message });
  }
});

// Heartbeat para atualizar last_seen
app.post('/api/devices/heartbeat', authenticate, [
  body('serial_number').notEmpty().withMessage('serial_number é obrigatório').trim(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Erros de validação: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { serial_number } = req.body;

    const device = await Device.findOneAndUpdate(
      { serial_number },
      { last_seen: new Date() },
      { new: true }
    );

    if (!device) {
      logger.warn(`Dispositivo não encontrado para heartbeat: ${serial_number}`);
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }

    logger.info(`Heartbeat recebido de: ${serial_number}`);
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
app.get('/api/devices/commands', authenticate, [
  query('serial_number').notEmpty().withMessage('serial_number é obrigatório').trim(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Erros de validação: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { serial_number } = req.query;

    const commands = await Command.find({ serial_number, status: 'pending' }).lean();
    if (commands.length > 0) {
      await Command.updateMany({ serial_number, status: 'pending' }, { status: 'sent' });
      logger.info(`Comandos pendentes encontrados para ${serial_number}: ${commands.length}`);
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
app.post('/api/executeCommand', authenticate, [
  body('serial_number').notEmpty().withMessage('serial_number é obrigatório').trim(),
  body('command').notEmpty().withMessage('command é obrigatório').trim(),
], async (req, res) => {
  const { device_name, serial_number, command, packageName, apkUrl, maintenance_status, maintenance_ticket, maintenance_history_entry } = req.body;

  try {
    if (!device_name || !command) {
      logger.warn('Faltam campos obrigatórios: device_name ou command');
      return res.status(400).json({ error: 'device_name e command são obrigatórios' });
    }

    if (command === 'set_maintenance') {
      if (typeof maintenance_status !== 'boolean') {
        logger.warn(`maintenance_status deve ser booleano para ${serial_number}`);
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
            logger.warn(`maintenance_history_entry inválido para ${serial_number}`);
            return res.status(400).json({ error: 'maintenance_history_entry deve conter timestamp e status' });
          }
          updateFields.$push = { maintenance_history: historyEntry };
        } catch (err) {
          logger.error(`Erro ao parsear maintenance_history_entry para ${serial_number}: ${err.message}`);
          return res.status(400).json({ error: 'Formato inválido para maintenance_history_entry' });
        }
      }

      const device = await Device.findOneAndUpdate(
        { serial_number },
        updateFields,
        { new: true }
      );

      if (!device) {
        logger.warn(`Dispositivo não encontrado: ${serial_number}`);
        return res.status(404).json({ error: 'Dispositivo não encontrado' });
      }

      logger.info(`Comando set_maintenance executado para ${serial_number}: status=${maintenance_status}`);
      return res.status(200).json({ message: `Status de manutenção atualizado para ${serial_number}` });
    } else {
      await Command.create({ 
        device_name, serial_number, 
        command, 
        parameters: { packageName, apkUrl }
      });
      logger.info(`Comando "${command}" registrado para ${serial_number}`);
      res.status(200).json({ message: `Comando ${command} registrado para ${device_name}` });
    }
  } catch (err) {
    logger.error(`Erro ao processar comando: ${err.message}`);
    return res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Reportar resultado de comando
app.post('/api/devices/command-result', authenticate, async (req, res) => {
  try {
    const { command_id, serial_number, success, result, error_message } = req.body;

    if (!serial_number && !command_id) {
      return res.status(400).json({ error: 'serial_number ou command_id é obrigatório' });
    }

    let command;
    if (command_id) {
      command = await Command.findByIdAndUpdate(command_id, {
        status: success ? 'completed' : 'failed',
        result: result || error_message,
        executedAt: new Date(),
      }, { new: true });
    } else {
      command = await Command.findOneAndUpdate(
        { serial_number, status: 'sent' },
        {
          status: success ? 'completed' : 'failed',
          result: result || error_message,
          executedAt: new Date()
        },
        { new: true, sort: { createdAt: -1 } }
      );
    }

    if (!command) {
      return res.status(404).json({ error: 'Comando não encontrado' });
    }

    logger.info(`Resultado do comando recebido: ${command.command} para ${serial_number} - ${success ? 'sucesso' : 'falha'}`);
    res.status(200).json({ message: 'Resultado do comando registrado' });

  } catch (err) {
    logger.error(`Erro ao registrar resultado do comando: ${err.message}`);
    return res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Excluir dispositivo
app.delete('/api/devices/:serial_number', authenticate, async (req, res) => {
  try {
    const { serial_number } = req.params;
    const device = await Device.findOneAndDelete({ serial_number: serial_number });
    if (!device) {
      logger.warn(`Dispositivo não encontrado: ${serial_number}`);
      return res.status(404).json({ error: 'Erro ao Dispositivo não encontrado' });
    }
    logger.info(`Dispositivo excluído: ${serial_number}`);
    res.status(200).json({ message: `Dispositivo ${serial_number} excluído com sucesso` });
  } catch (err) {
    logger.error(`Erro ao excluir dispositivo: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor', details: err.message });
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

// Listar APKs na pasta public
app.get('/api/apks', authenticate, async (req, res) => {
  try {
    const publicDir = path.join(__dirname, 'public');
    const files = await fs.readdir(publicDir);
    const apks = files.filter(file => file.endsWith('.apk')).map(file => ({
      name: file,
      url: `http://${getLocalIPAddress()}:${port}/public/${file}`
    }));
    logger.info(`Listando ${apks.length} APKs disponíveis`);
    res.status(200).json(apks);
  } catch (err) {
    logger.error(`Erro ao listar APKs: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para o painel web
app.get('/', (req, res) => {
  res.render('index', { token: process.env.AUTH_TOKEN });
});

// Rota para o dashboard
app.get('/dashboard', authenticate, async (req, res) => {
  try {
    const devices = await Device.find().lean();
    const publicDir = path.join(__dirname, 'public');
    const files = await fs.readdir(publicDir);
    const apks = files.filter(file => file.endsWith('.apk')).map(file => ({
      name: file,
      url: `http://${getLocalIPAddress()}:${port}/public/${file}`
    }));
    res.render('dashboard', { devices, apks, serverUrl: `http://${getLocalIPAddress()}:${port}` });
  } catch (err) {
    logger.error(`Erro ao carregar dashboard: ${err.message}`);
    res.status(500).send('Erro interno do servidor');
  }
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
  logger.info(`📊 Dashboard disponível em: http://${getLocalIPAddress()}:${port}/dashboard`);
});