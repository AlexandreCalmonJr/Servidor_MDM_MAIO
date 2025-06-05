import compression from 'compression';
import cors from 'cors';
import crypto from 'crypto';
import dotenv from 'dotenv';
import express from 'express';
import rateLimit from 'express-rate-limit';
import { body, query, validationResult } from 'express-validator';
import { promises as fs } from 'fs';
import mongoose from 'mongoose';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import winston from 'winston';

// Equivalente ES module do __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Carregar variáveis de ambiente
dotenv.config();

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
  windowMs: 15 * 60 * 1000, // 15 minutos
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
    logger.warn(`Tentativa de acesso sem token: ${req.ip} para ${req.method} ${req.url}`);
    return res.status(401).json({ error: 'Token de autenticação não fornecido' });
  }
  if (token !== process.env.AUTH_TOKEN) {
    logger.warn(`Token inválido fornecido por ${req.ip}: ${token}`);
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
  device_name: { type: String, required: true, trim: false },
  device_model: { type: String, trim: false, default: 'N/A' },
  device_id: { type: String, required: true, trim: false },
  serial_number: { type: String, unique: true, trim: false, sparse: true, default: 'N/A' },
  imei: { type: String, unique: true, trim: false, sparse: true, default: 'N/A' },
  battery: { type: Number, min: 0, max: 100, default: null },
  network: { type: String, trim: false, default: 'N/A' },
  host: { type: String, trim: false, default: 'N/A' },
  sector: { type: String, trim: false, default: 'Desconhecido' },
  floor: { type: String, trim: false, default: 'Desconhecido' },
  mac_address_radio: { type: String, trim: false, default: 'N/A' },
  last_sync: { type: String, trim: false, default: 'N/A' },
  secure_android_id: { type: String, trim: false, default: 'N/A' },
  ip_address: { type: String, trim: false, default: 'N/A' },
  wifi_ipv6: { type: String, trim: false, default: 'N/A' },
  wifi_gateway_ip: { type: String, trim: false, default: 'N/A' },
  wifi_broadcast: { type: String, trim: false, default: 'N/A' },
  wifi_submask: { type: String, trim: false, default: 'N/A' },
  last_seen: { type: String, trim: false },
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

DeviceSchema.pre('validate', function (next) {
  if (!this.imei && !this.serial_number) {
    // Alterado para não barrar durante o provisionamento inicial via QR,
    // onde esses dados podem ainda não estar disponíveis.
    // A validação mais estrita pode ocorrer em /api/devices/data ou no lado do cliente.
  }
  next();
});

DeviceSchema.index({ serial_number: 1 }, { unique: true, sparse: true });
DeviceSchema.index({ mac_address_radio: 1 }, { unique: true });
DeviceSchema.index({ last_seen: 1 });

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
    logger.debug(`Nenhum mac_address_radio fornecido: ${mac_address_radio}`);
    return { sector: 'Desconhecido', floor: 'Desconhecido' };
  }
  const mapping = await BssidMapping.findOne({ mac_address_radio: mac_address_radio });
  if (!mapping) {
    logger.debug(`Nenhum mapeamento encontrado para mac_address_radio: ${mac_address_radio}`);
    return { sector: 'Desconhecido', floor: 'Desconhecido' };
  }
  logger.debug(`Mapeamento encontrado para ${mac_address_radio}: ${mapping.sector}, ${mapping.floor}`);
  return { sector: mapping.sector, floor: mapping.floor };
}

// Modelo de mapeamento de unidades por faixa de IP
const UnitMappingSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true, trim: false },
  ip_range_start: { type: String, required: true, trim: false },
  ip_range_end: { type: String, required: true, trim: false },
  created_at: { type: Date, default: Date.now },
});

const UnitMapping = mongoose.model('UnitMapping', UnitMappingSchema);

function ipToInt(ip) {
  if (!ip || typeof ip !== 'string') return 0;
  const parts = ip.split('.').map(Number);
  if (parts.some(isNaN) || parts.length !== 4) return 0;
  return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

async function mapIpToUnit(ip_address) {
  if (!ip_address || ip_address === 'N/A') {
    return 'Desconhecido';
  }
  try {
    const units = await UnitMapping.find();
    const ipInt = ipToInt(ip_address);
    if (ipInt === 0 && ip_address !== '0.0.0.0') { // Checagem se ipToInt falhou para IP válido
        logger.warn(`IP ${ip_address} resultou em 0 no ipToInt, mas não é 0.0.0.0.`);
        return 'Desconhecido (IP Inválido)';
    }
    for (const unit of units) {
      const startInt = ipToInt(unit.ip_range_start);
      const endInt = ipToInt(unit.ip_range_end);
      if (ipInt >= startInt && ipInt <= endInt) {
        return unit.name;
      }
    }
    return 'Desconhecido';
  } catch (error) {
      logger.error(`Erro ao mapear IP ${ip_address} para unidade: ${error.message}`);
      return 'Erro no Mapeamento';
  }
}

// === ROTAS ===

// Gerar token de provisionamento
app.post('/api/provisioning/generate-token', authenticate, async (req, res) => { //
  try {
    const { organization, config_profile, max_uses = 1, expires_in_hours = 24 } = req.body;

    if (!organization || !config_profile) {
      return res.status(400).json({ error: 'organization e config_profile são obrigatórios' });
    }

    const profile = await ConfigProfile.findOne({ name: config_profile }); //
    if (!profile) {
      return res.status(404).json({ error: 'Perfil de configuração não encontrado' }); //
    }

    const tokenValue = crypto.randomBytes(32).toString('hex');
    const expires_at = new Date(Date.now() + expires_in_hours * 60 * 60 * 1000);

    const provisioningToken = new ProvisioningToken({
      token: tokenValue,
      organization,
      config_profile,
      max_uses,
      expires_at
    });


    logger.info(`Token de provisionamento gerado: ${tokenValue} para ${organization} com perfil ${config_profile}`);
    res.status(201).json({
      token: tokenValue,
      organization,
      config_profile,
      max_uses,
      expires_at,
      // A URL de provisionamento web pode ser mantida se você ainda a usa
      provisioning_url_web: `http://${getLocalIPAddress()}:${port}/provision/${tokenValue}`
    });
  } catch (err) {
    logger.error(`Erro ao gerar token de provisionamento: ${err.message} - Stack: ${err.stack}`);
    res.status(500).json({ error: 'Erro interno do servidor', details: err.message });
  }
});

app.post('/api/provisioning/qr-payload', authenticate, async (req, res) => {
  try {
    const {
        organization,
        config_profile_name, // Nome do perfil de configuração a ser usado
        apk_file_name = 'mdm_client_base.apk',
        apk_signature_checksum, // Nome do seu APK na pasta /public
        wifi_ssid, // Opcional: SSID da rede Wi-Fi para o dispositivo se conectar
        wifi_password, // Opcional: Senha da rede Wi-Fi
        wifi_security_type = 'WPA', // Opcional: Tipo de segurança (WPA, WEP, NONE)
        skip_encryption = true, // Opcional
        leave_all_system_apps_enabled = true // Opcional
    } = req.body;

    if (!organization || !config_profile_name) {
      return res.status(400).json({ error: 'Campos organization e config_profile_name são obrigatórios.' });
    }

    // 1. Validar se o perfil de configuração existe
    const profile = await ConfigProfile.findOne({ name: config_profile_name });
    if (!profile) {
      return res.status(404).json({ error: `Perfil de configuração '${config_profile_name}' não encontrado.` });
    }

    // 2. Gerar um token de provisionamento (pode reutilizar lógica ou chamar o endpoint internamente)
    // Para simplicidade, vamos gerar um novo token aqui, mas você pode refatorar
    const provisioningTokenValue = crypto.randomBytes(32).toString('hex');
    const expiresInMillis = (24 * 60 * 60 * 1000); // 24 horas
    const expires_at = new Date(Date.now() + expiresInMillis); // Expira em 24 horas

    const newProvisioningToken = new ProvisioningToken({
      token: provisioningTokenValue,
      organization,
      config_profile: config_profile_name,
      max_uses: 1, // Típico para QR codes de uso único, ajuste se necessário
      expires_at,
      is_active: true
    });
    await newProvisioningToken.save();
    logger.info(`QR_TOKEN_GEN: Token ${provisioningTokenValue} salvo. Expira em: ${expires_at.toISOString()} (UTC)`);

    // 3. Construir o JSON do QR Code
    const qrCodeJson = {
      "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "com.example.mdm_client_base/.DeviceAdminReceiver",
      "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME": "com.example.mdm_client_base",
      "android.app.extra.PROVISIONING_DOWNLOAD_URL": downloadUrl,
      "android.app.extra.PROVISIONING_SKIP_ENCRYPTION": true, // Ou configurável
      "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED": true, // Ou configurável
      // Adicionar campos padrão de localidade e fuso horário
      "android.app.extra.PROVISIONING_LOCALE": "pt_BR",
      "android.app.extra.PROVISIONING_TIME_ZONE": "America/Sao_Paulo", // Ajuste conforme sua necessidade
      "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE": {
        "server_url": serverUrlForClient,
        "provisioning_token": provisioningTokenValue, // O token gerado e salvo
        "auth_token_main": process.env.AUTH_TOKEN
      }
    };

    if (apk_signature_checksum && apk_signature_checksum.trim() !== "") {
      qrCodeJson["android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM"] = apk_signature_checksum.trim();
      logger.info(`QR_PAYLOAD_GEN: Incluindo checksum de assinatura: ${apk_signature_checksum.trim()}`);
    } else {
      logger.info(`QR_PAYLOAD_GEN: Checksum de assinatura não fornecido.`);
    }

    if (wifi_ssid) {
      qrCodeJson["android.app.extra.PROVISIONING_WIFI_SSID"] = wifi_ssid;
      if (wifi_password) qrCodeJson["android.app.extra.PROVISIONING_WIFI_PASSWORD"] = wifi_password;
      qrCodeJson["android.app.extra.PROVISIONING_WIFI_SECURITY_TYPE"] = wifi_security_type;
    }

    logger.info(`QR_PAYLOAD_GEN: Payload gerado para ${organization}: ${JSON.stringify(qrCodeJson).substring(0, 200)}...`);
    res.status(200).json(qrCodeJson);

  } catch (err) {
    logger.error(`QR_PAYLOAD_ERR: ${err.message} - Stack: ${err.stack}`);
    res.status(500).json({ error: 'Erro interno ao gerar payload QR.', details: err.message });
  }
});

// Endpoint de provisionamento
app.post('/api/provisioning/enroll', enrollLimiter, async (req, res) => { //
  try {
    const {
      provisioning_token, // Este é o token que veio do QR Code (ADMIN_EXTRAS_BUNDLE)
      device_id,          // ID do dispositivo Android
      device_name,
      device_model,
      serial_number,      // Importante para identificar unicamente
      imei,
      secure_android_id,
      ip_address,
      mac_address_radio,
    } = req.body;

    logger.info(`ENROLL_REQ: Recebido para serial ${serial_number}, token ${provisioning_token ? provisioning_token.substring(0,10) + '...' : 'N/A'}`);

    if (!provisioning_token || !device_id || !device_name || !serial_number) {
      logger.warn(`ENROLL_FAIL: Campos obrigatórios ausentes. SN: ${serial_number}, Token: ${provisioning_token}`);
      return res.status(400).json({ error: 'provisioning_token, device_id, device_name e serial_number são obrigatórios' });
    }

    const agoraNoServidor = new Date();
    logger.info(`ENROLL_CHECK: Verificando token ${provisioning_token}. Agora (servidor UTC): ${agoraNoServidor.toISOString()}`);

    const tokenEntry = await ProvisioningToken.findOne({
      token: provisioning_token,
      is_active: true, // Verifica se está ativo
      // Removido o filtro de expiração daqui para logar melhor abaixo
    });

    if (!tokenEntry) {
      logger.warn(`ENROLL_FAIL: Token ${provisioning_token} não encontrado ou inativo na DB.`);
      // Tenta buscar sem is_active para ver se existe mas está inativo
      const existeInativo = await ProvisioningToken.findOne({ token: provisioning_token });
      if (existeInativo) logger.warn(`ENROLL_FAIL_DETAIL: Token ${provisioning_token} existe mas is_active=${existeInativo.is_active}.`);
      return res.status(401).json({ error: 'Token de provisionamento inválido ou inativo.' });
    }

    // Verificação explícita de expiração
    if (tokenEntry.expires_at <= agoraNoServidor) {
        logger.warn(`ENROLL_FAIL: Token ${provisioning_token} está EXPIRADO. Expira em: ${tokenEntry.expires_at.toISOString()}, Agora: ${agoraNoServidor.toISOString()}`);
        // Opcional: Desativar token expirado
        // tokenEntry.is_active = false;
        // await tokenEntry.save();
        return res.status(401).json({ error: `Token de provisionamento expirado. (Expirou em: ${tokenEntry.expires_at.toLocaleString('pt-BR')})` });
    }

    logger.info(`ENROLL_CHECK: Token ${provisioning_token} encontrado. Expira em: ${tokenEntry.expires_at.toISOString()}. Usos: ${tokenEntry.used_count}/${tokenEntry.max_uses}`);

    if (tokenEntry.used_count >= tokenEntry.max_uses) {
      logger.warn(`ENROLL_FAIL: Token ${provisioning_token} esgotado (usos: ${tokenEntry.used_count}/${tokenEntry.max_uses}).`);
      tokenEntry.is_active = false; // Desativa token esgotado
      await tokenEntry.save();
      return res.status(401).json({ error: 'Token de provisionamento esgotado.' });
    }

    let device = await Device.findOne({ serial_number: serial_number });
    const configProfile = await ConfigProfile.findOne({ name: tokenEntry.config_profile });
    if (!configProfile) {
      logger.error(`ENROLL_FAIL: Perfil de configuração '${tokenEntry.config_profile}' associado ao token não encontrado.`);
      return res.status(500).json({ error: 'Perfil de configuração associado ao token não encontrado.' });
    }

    if (device && device.provisioning_status === 'completed') {
      logger.warn(`Dispositivo (serial: ${serial_number}) já provisionado e completo.`);
      // Você pode optar por atualizar o dispositivo ou retornar erro.
      // Por ora, vamos permitir a atualização se o token for válido.
      // return res.status(409).json({ error: 'Dispositivo já provisionado (completo)' });
    }


    const location = await mapMacAddressRadioToLocation(mac_address_radio || 'N/A');
    const unitName = await mapIpToUnit(ip_address || 'N/A');


    const deviceData = {
      device_name,
      device_model: device_model || 'N/A',
      device_id, // Android ID
      serial_number,
      imei: imei || 'N/A',
      secure_android_id: secure_android_id || 'N/A',
      ip_address: ip_address || 'N/A',
      mac_address_radio: mac_address_radio || 'N/A',
      // ... outros campos ...
      sector: location.sector,
      floor: location.floor,
      unit: unitName,
      provisioning_status: 'in_progress', // Marcado como 'in_progress'
      provisioning_token: provisioning_token, // Salva o token usado
      configuration_profile: tokenEntry.config_profile,
      owner_organization: tokenEntry.organization,
      enrollment_date: device ? device.enrollment_date : new Date(), // Mantém data original se já existia
      last_seen: new Date().toISOString()
    };

    if (device) {
      Object.assign(device, deviceData);
      logger.info(`ENROLL_UPDATE: Atualizando dispositivo existente ${serial_number}`);
    } else {
      deviceData.enrollment_date = agoraNoServidor; // Definir data de enrollment apenas para novos
      device = new Device(deviceData);
      logger.info(`ENROLL_NEW: Criando novo dispositivo ${serial_number}`);
    }
    await device.save();

    tokenEntry.used_count += 1;
    if (tokenEntry.used_count >= tokenEntry.max_uses) {
        tokenEntry.is_active = false;
        logger.info(`ENROLL_TOKEN_UPDATE: Token ${provisioning_token} desativado após uso ${tokenEntry.used_count}.`);
    }
    await tokenEntry.save();
    // Lógica para criar comandos iniciais (mantida)
    const initialCommands = [];
    if (configProfile.settings.mandatory_apps && configProfile.settings.mandatory_apps.length > 0) { //
        for (const app of configProfile.settings.mandatory_apps) {
            initialCommands.push({ //
                device_name: device.device_name, // Usar o nome do dispositivo do objeto 'device'
                serial_number: device.serial_number, // Usar o serial_number do objeto 'device'
                command: 'install_app', //
                parameters: { //
                    package_name: app.package_name, //
                    apk_url: app.apk_url, //
                    version: app.version //
                }
            });
        }
    }
    // ... (outros comandos como apply_restrictions, configure_wifi) ...
    if (configProfile.settings.restrictions) { //
        initialCommands.push({ //
            device_name: device.device_name,
            serial_number: device.serial_number,
            command: 'apply_restrictions', //
            parameters: configProfile.settings.restrictions //
        });
    }
    if (configProfile.settings.wifi_configs && configProfile.settings.wifi_configs.length > 0) { //
        initialCommands.push({ //
            device_name: device.device_name,
            serial_number: device.serial_number,
            command: 'configure_wifi', //
            parameters: { wifi_configs: configProfile.settings.wifi_configs } //
        });
    }


    if (initialCommands.length > 0) {
      await Command.insertMany(initialCommands);
    }

    logger.info(`Dispositivo (serial: ${serial_number}) provisionado (enroll) com sucesso para ${tokenEntry.organization}. Status: in_progress.`);
    res.status(200).json({
      message: 'Dispositivo provisionado (enroll) com sucesso. Aguardando conclusão.',
      deviceId: device.device_id, // Usar o ID do dispositivo Android
      serial_number: device.serial_number,
      organization: tokenEntry.organization,
      config_profile: tokenEntry.config_profile,
      initial_commands_count: initialCommands.length
    });

  } catch (err) {
    if (err.code === 11000 && err.keyPattern && (err.keyPattern.serial_number || err.keyPattern.imei)) {
        // Trata erro de duplicidade de forma mais específica
        const field = err.keyPattern.serial_number ? 'serial_number' : 'imei';
        const value = err.keyValue[field];
        logger.error(`Erro de duplicidade no enrollment para ${field}: ${value}. Erro: ${err.message}`);
        return res.status(409).json({ error: `Dispositivo com este ${field} (${value}) já existe.`, field, value });
    }
    logger.error(`Erro no endpoint de provisionamento (enroll): ${err.message}, Stack: ${err.stack}`);
    res.status(500).json({ error: 'Erro interno do servidor durante o enrollment.', details: err.message });
  }
});
// Finalizar provisionamento
app.post('/api/provisioning/complete', authenticate, async (req, res) => { //
  try {
    const { device_id, serial_number, success, error_message } = req.body; // device_id aqui é o Android ID

    // Priorizar serial_number para encontrar o dispositivo
    if (!serial_number) {
      logger.warn('serial_number ausente ao finalizar provisionamento');
      return res.status(400).json({ error: 'serial_number é obrigatório' });
    }

    const device = await Device.findOne({ serial_number: serial_number });
    if (!device) {
      logger.warn(`Dispositivo (serial: ${serial_number}) não encontrado ao tentar finalizar provisionamento.`);
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }

    // Se o device_id (Android ID) também foi enviado, podemos verificar se bate, como uma segurança adicional
    if (device_id && device.device_id !== device_id) {
        logger.warn(`Conflito de device_id para serial_number ${serial_number}. Esperado: ${device.device_id}, Recebido: ${device_id}. Ignorando por ora.`);
    }


    device.provisioning_status = success ? 'completed' : 'failed'; //
    if (!success && error_message) {
      // Você pode querer um campo específico para erros de provisionamento
      // device.provisioning_error = error_message;
      logger.error(`Provisionamento falhou para ${serial_number}: ${error_message}`);
    }
    device.compliance_status = success ? 'compliant' : 'non_compliant'; //
    // device.last_seen = new Date().toISOString(); // Atualiza last_seen

    await device.save();

    logger.info(`ENROLL_SUCCESS: Dispositivo ${serial_number} para ${tokenEntry.organization}. Status: in_progress.`);
    res.status(200).json({
      message: 'Dispositivo em processo de provisionamento. Aguardando conclusão do cliente.',
      deviceId: device.device_id,
      serial_number: device.serial_number,
    });

  } catch (err) {
    logger.error(`ENROLL_ERR: ${err.message} para token ${req.body.provisioning_token}, SN ${req.body.serial_number} - Stack: ${err.stack}`);
    res.status(500).json({ error: 'Erro interno no servidor durante o enrollment.', details: err.message });
  }
});

// Criar perfil de configuração
app.post('/api/config-profiles', authenticate, async (req, res) => { //
  try {
    const profileData = req.body;

    if (!profileData.name) {
      logger.warn('Nome do perfil ausente ao criar ConfigProfile');
      return res.status(400).json({ error: 'Nome do perfil é obrigatório' }); //
    }

    // Validação básica da estrutura de settings
    if (!profileData.settings || typeof profileData.settings !== 'object') {
        return res.status(400).json({ error: 'O campo settings é obrigatório e deve ser um objeto.'});
    }
     if (profileData.settings.mandatory_apps) {
        if (!Array.isArray(profileData.settings.mandatory_apps)) {
            return res.status(400).json({ error: 'mandatory_apps deve ser um array.' });
        }
        for (const app of profileData.settings.mandatory_apps) {
            if (!app.package_name || !app.apk_url) {
                 return res.status(400).json({ error: 'Cada app em mandatory_apps deve ter package_name e apk_url.' });
            }
        }
    }
  
  // LISTAR todos os Perfis de Configuração
app.get('/api/config-profiles', authenticate, async (req, res) => {
  try {
    const profiles = await ConfigProfile.find().lean();
    logger.info(`Listando ${profiles.length} perfis de configuração.`);
    res.status(200).json(profiles);
  } catch (err) {
    logger.error(`Erro ao listar perfis de configuração: ${err.message} - Stack: ${err.stack}`);
    res.status(500).json({ error: 'Erro interno do servidor ao listar perfis.', details: err.message });
  }
});

// OBTER um Perfil de Configuração específico pelo nome
app.get('/api/config-profiles/:profileName', authenticate, async (req, res) => {
  try {
    const { profileName } = req.params;
    const profile = await ConfigProfile.findOne({ name: profileName }).lean();
    if (!profile) {
      logger.warn(`Perfil de configuração '${profileName}' não encontrado.`);
      return res.status(404).json({ error: `Perfil de configuração '${profileName}' não encontrado.` });
    }
    logger.info(`Perfil de configuração '${profileName}' encontrado.`);
    res.status(200).json(profile);
  } catch (err) {
    logger.error(`Erro ao obter o perfil de configuração '${req.params.profileName}': ${err.message} - Stack: ${err.stack}`);
    res.status(500).json({ error: 'Erro interno do servidor ao obter o perfil.', details: err.message });
  }
});

// ATUALIZAR um Perfil de Configuração existente
app.put('/api/config-profiles/:profileName', authenticate, async (req, res) => {
  try {
    const { profileName } = req.params;
    const updateData = req.body;

    // Não permitir alteração do nome do perfil via este endpoint para simplicidade.
    // Se a alteração do nome for necessária, pode ser um processo mais complexo
    // de verificar duplicidade ou pode ser feito por exclusão/recriação.
    if (updateData.name && updateData.name !== profileName) {
      return res.status(400).json({ error: 'A alteração do nome do perfil não é permitida por esta rota. Exclua e crie um novo se necessário.' });
    }
    // Remove 'name' do updateData para garantir que não seja alterado acidentalmente.
    delete updateData.name;
    updateData.updated_at = new Date(); // Atualiza o timestamp

    // Validação básica da estrutura de settings (similar à da criação)
    if (updateData.settings && typeof updateData.settings !== 'object') {
        return res.status(400).json({ error: 'O campo settings, se fornecido, deve ser um objeto.'});
    }
    if (updateData.settings && updateData.settings.mandatory_apps) {
        if (!Array.isArray(updateData.settings.mandatory_apps)) {
            return res.status(400).json({ error: 'mandatory_apps deve ser um array.' });
        }
        for (const app of updateData.settings.mandatory_apps) {
            if (!app.package_name || !app.apk_url) {
                 return res.status(400).json({ error: 'Cada app em mandatory_apps deve ter package_name e apk_url.' });
            }
        }
    }
    // Adicione mais validações para wifi_configs, restrictions conforme necessário

    const updatedProfile = await ConfigProfile.findOneAndUpdate(
      { name: profileName },
      { $set: updateData },
      { new: true, runValidators: true } // new: true retorna o documento atualizado, runValidators para garantir schema
    );

    if (!updatedProfile) {
      logger.warn(`Perfil de configuração '${profileName}' não encontrado para atualização.`);
      return res.status(404).json({ error: `Perfil de configuração '${profileName}' não encontrado.` });
    }

    logger.info(`Perfil de configuração '${profileName}' atualizado com sucesso.`);
    res.status(200).json(updatedProfile);
  } catch (err) {
    if (err.code === 11000) { // Caso tente mudar para um nome que já existe (se 'name' não fosse removido)
        logger.warn(`Erro de duplicidade ao atualizar perfil: ${err.message}`);
        return res.status(409).json({ error: 'Erro de duplicidade ao tentar atualizar o perfil.', details: err.message });
    }
    logger.error(`Erro ao atualizar o perfil de configuração '${req.params.profileName}': ${err.message} - Stack: ${err.stack}`);
    res.status(500).json({ error: 'Erro interno do servidor ao atualizar o perfil.', details: err.message });
  }
});

// EXCLUIR um Perfil de Configuração
app.delete('/api/config-profiles/:profileName', authenticate, async (req, res) => {
  try {
    const { profileName } = req.params;

    // Opcional: Verificar se o perfil está em uso antes de excluir
    const tokensUsandoPerfil = await ProvisioningToken.countDocuments({ config_profile: profileName, is_active: true });
    if (tokensUsandoPerfil > 0) {
      logger.warn(`Tentativa de excluir perfil '${profileName}' que está em uso por ${tokensUsandoPerfil} token(s) de provisionamento ativo(s).`);
      return res.status(400).json({ error: `Não é possível excluir o perfil '${profileName}' pois ele está associado a ${tokensUsandoPerfil} token(s) de provisionamento ativo(s).` });
    }
    // Você também pode querer verificar se algum dispositivo 'Device' está usando este perfil.

    const result = await ConfigProfile.deleteOne({ name: profileName });

    if (result.deletedCount === 0) {
      logger.warn(`Perfil de configuração '${profileName}' não encontrado para exclusão.`);
      return res.status(404).json({ error: `Perfil de configuração '${profileName}' não encontrado.` });
    }

    logger.info(`Perfil de configuração '${profileName}' excluído com sucesso.`);
    res.status(200).json({ message: `Perfil de configuração '${profileName}' excluído com sucesso.` });
  } catch (err) {
    logger.error(`Erro ao excluir o perfil de configuração '${req.params.profileName}': ${err.message} - Stack: ${err.stack}`);
    res.status(500).json({ error: 'Erro interno do servidor ao excluir o perfil.', details: err.message });
  }
});

    const profile = new ConfigProfile(profileData);
    await profile.save();

    logger.info(`Perfil de configuração criado: ${profileData.name}`);
    res.status(201).json(profile);

  } catch (err) {
    if (err.code === 11000) { // Erro de chave duplicada (nome do perfil já existe)
      logger.warn(`Tentativa de criar perfil de configuração com nome já existente: ${req.body.name}`);
      return res.status(409).json({ error: 'Perfil com este nome já existe' }); //
    }
    logger.error(`Erro ao criar perfil de configuração: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor', details: err.message });
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
    logger.warn(`Erros de validação em /api/devices/data: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    let data = req.body;
    logger.info(`Dados recebidos de ${data.serial_number || data.imei || req.ip} para /api/devices/data: ${Object.keys(data).length} campos`);

    if (!data.serial_number && !data.imei) {
        logger.warn(`Chamada para /api/devices/data sem serial_number ou imei.`);
        return res.status(400).json({ error: 'serial_number ou imei são obrigatórios para identificar o dispositivo.' });
    }

    const identifier = data.serial_number ? { serial_number: data.serial_number } : { imei: data.imei };

    const location = await mapMacAddressRadioToLocation(data.mac_address_radio || 'N/A');
    const unitName = await mapIpToUnit(data.ip_address || 'N/A');

    const deviceData = {
      // Atualize apenas os campos que fazem sentido serem atualizados por esta rota
      device_name: data.device_name, // Pode mudar
      device_model: data.device_model, // Geralmente não muda, mas pode ser atualizado
      battery: data.battery != null ? data.battery : undefined, // Não sobrescrever com null se não vier
      network: data.network,
      host: data.host,
      sector: location.sector,
      floor: location.floor,
      mac_address_radio: data.mac_address_radio,
      last_sync: data.last_sync || new Date().toISOString(),
      secure_android_id: data.secure_android_id, // Pode ser atualizado
      ip_address: data.ip_address,
      wifi_ipv6: data.wifi_ipv6,
      wifi_gateway_ip: data.wifi_gateway_ip,
      wifi_broadcast: data.wifi_broadcast,
      wifi_submask: data.wifi_submask,
      last_seen: data.last_seen || new Date().toISOString(),
      unit: unitName,
      // Campos como provisioning_status, configuration_profile, owner_organization, enrollment_date
      // geralmente não são atualizados por esta rota de dados, mas pelo fluxo de provisionamento.
    };

    // Remover campos undefined para não sobrescrever com null no MongoDB via $set
    Object.keys(deviceData).forEach(key => deviceData[key] === undefined && delete deviceData[key]);


    const device = await Device.findOneAndUpdate(
      identifier, // Encontra por serial_number ou imei
      { $set: deviceData, $setOnInsert: { // $setOnInsert para campos que só devem ser definidos na criação se o upsert criar
            device_id: data.device_id || 'unknown_on_data_upsert', // Android ID
            serial_number: data.serial_number, // Garantir que seja definido se o upsert criar por IMEI
            imei: data.imei, // Garantir que seja definido se o upsert criar por Serial
            provisioning_status: 'completed', // Se está enviando dados, assume-se provisionado
            enrollment_date: new Date(),
       }},
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    logger.info(`Dispositivo ${device.serial_number || device.imei} salvo/atualizado com sucesso via /api/devices/data`);
    res.status(200).json({ message: 'Dados salvos com sucesso', deviceId: device._id }); // deviceId do MongoDB
  } catch (err) {
    if (err.code === 11000) {
      const field = err.keyValue?.serial_number ? 'serial_number' : 'imei';
      const value = err.keyValue?.serial_number || err.keyValue?.imei;
      logger.error(`Erro de duplicidade em /api/devices/data para ${field}: ${value}. Erro: ${err.message}`);
      return res.status(409).json({ error: `Dispositivo com este ${field} (${value}) já existe.`, field, value });
    }
    logger.error(`Erro ao salvar dados de ${req.body.serial_number || req.body.imei || req.ip} em /api/devices/data: ${err.message} - Stack: ${err.stack}`);
    return res.status(500).json({ error: 'Erro interno do servidor', details: err.message });
  }
});
// Middleware de autenticação

// Heartbeat para atualizar last_seen
app.post('/api/devices/heartbeat', authenticate, [ //
  body('serial_number').notEmpty().withMessage('serial_number é obrigatório').trim(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Erros de validação no heartbeat: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { serial_number } = req.body;

    const device = await Device.findOneAndUpdate(
      { serial_number: serial_number },
      { last_seen: new Date().toISOString() }, // Usar toISOString para consistência
      { new: true }
    );

    if (!device) {
      logger.warn(`Dispositivo não encontrado para heartbeat: ${serial_number}`);
      return res.status(404).json({ error: 'Dispositivo não encontrado' }); //
    }

    logger.info(`Heartbeat recebido de: ${serial_number}`);
    res.status(200).json({ message: 'Heartbeat registrado com sucesso' });
  } catch (err) {
    logger.error(`Erro no heartbeat de ${req.body.serial_number || req.ip}: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Listar dispositivos
app.get('/api/devices', authenticate, async (req, res) => { //
  try {
    const devices = await Device.find().lean();
    const devicesWithUnit = await Promise.all(devices.map(async (device) => {
      const unit = await mapIpToUnit(device.ip_address); //
      return { ...device, unit }; //
    }));
    logger.info(`Lista de dispositivos retornada: ${devicesWithUnit.length} dispositivos`);
    res.status(200).json(devicesWithUnit);
  } catch (err) {
    logger.error(`Erro ao obter dispositivos: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Obter comandos pendentes
app.get('/api/devices/commands', authenticate, [ //
  query('serial_number').notEmpty().withMessage('serial_number é obrigatório').trim(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Erros de validação ao obter comandos: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { serial_number } = req.query;

    // Verifica se o dispositivo existe e está ativo/completo
    const device = await Device.findOne({ serial_number: serial_number, provisioning_status: 'completed' });
    if (!device) {
        logger.warn(`Tentativa de obter comandos para dispositivo não encontrado ou não completamente provisionado: ${serial_number}`);
        return res.status(404).json({ error: 'Dispositivo não encontrado ou não pronto para receber comandos.' });
    }


    const commands = await Command.find({ serial_number: serial_number, status: 'pending' }).lean(); //
    if (commands.length > 0) {
      // Atualiza status para 'sent' APENAS para os comandos que estão sendo enviados
      const commandIds = commands.map(cmd => cmd._id);
      await Command.updateMany({ _id: { $in: commandIds } }, { status: 'sent' }); //
      logger.info(`Comandos pendentes enviados para ${serial_number}: ${commands.length}`);
    }

    res.status(200).json(commands.map(cmd => ({
      id: cmd._id.toString(),
      command_type: cmd.command, //
      parameters: cmd.parameters //
    })));
  } catch (err) {
    logger.error(`Erro ao obter comandos para ${req.query.serial_number}: ${err.message}`);
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
    if (!serial_number || !command) {
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
        device_name, 
        serial_number, 
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
      logger.warn('serial_number ou command_id ausente');
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
      logger.warn(`Comando não encontrado para serial_number: ${serial_number}`);
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
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
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

// Listar APKs na pasta public (ajustado para compatibilidade com Flutter)
app.get('/public/apks.json', async (req, res) => {
  try {
    const publicDir = path.join(__dirname, 'public');
    const files = await fs.readdir(publicDir);
    const apks = await Promise.all(
      files
        .filter(file => file.toLowerCase().endsWith('.apk'))
        .map(async (file) => {
          const stats = await fs.stat(path.join(publicDir, file));
          return {
            name: file,
            url: `http://${getLocalIPAddress()}:${port}/public/${file}`,
            size: stats.size, // Tamanho em bytes
            lastModified: stats.mtime // Data de modificação
          };
        })
    );
    logger.info(`Listando ${apks.length} APKs disponíveis na pasta public`);
    res.status(200).json(apks);
  } catch (err) {
    logger.error(`Erro ao listar APKs: ${err.message}`);
    res.status(500).json({ error: 'Erro ao listar APKs', details: err.message });
  }
});

// Rota para o painel web
app.get('/', (req, res) => {
  res.render('index', { token: process.env.AUTH_TOKEN });
});

// Rota para o dashboard
// Linha MODIFICADA no seu server.js
app.get('/dashboard', async (req, res) => { // Middleware 'authenticate' REMOVIDO daqui
  try {
    // A lógica para buscar devices e apks ainda pode ser útil aqui
    // se você quiser passar alguns dados iniciais, mas eles não estarão
    // "protegidos" por este token específico nesta etapa de carregamento da página.
    // A proteção real das funcionalidades virá das chamadas API feitas pelo JavaScript do dashboard.
    const devices = await Device.find().lean();
    const publicDir = path.join(__dirname, 'public');
    const files = await fs.readdir(publicDir);
    const apks = files.filter(file => file.endsWith('.apk')).map(file => ({
      name: file,
      url: `http://${getLocalIPAddress()}:${port}/public/${file}`
    }));
    res.render('dashboard', { devices, apks, serverUrl: `http://${getLocalIPAddress()}:${port}` });
  } catch (err) {
    logger.error(`Erro ao carregar dados para o dashboard (rota não autenticada): ${err.message}`);
    // Você pode querer renderizar o dashboard mesmo com erro ou uma página de erro simples
    res.status(500).render('dashboard', { devices: [], apks: [], serverUrl: `http://${getLocalIPAddress()}:${port}`, error: "Erro ao carregar dados iniciais." });
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

// Criar mapeamento de unidade
const isValidIPv4 = (ip) => {
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
};

app.post('/api/units', authenticate, async (req, res) => {
  try {
    const { name, ip_range_start, ip_range_end } = req.body;
    if (!name || !ip_range_start || !ip_range_end) {
      return res.status(400).json({ error: 'name, ip_range_start e ip_range_end são obrigatórios' });
    }
    if (!isValidIPv4(ip_range_start) || !isValidIPv4(ip_range_end)) {
      return res.status(400).json({ error: 'ip_range_start e ip_range_end devem ser IPs válidos no formato xxx.xxx.xxx.xxx' });
    }
    const startInt = ipToInt(ip_range_start);
    const endInt = ipToInt(ip_range_end);
    if (startInt > endInt) {
      return res.status(400).json({ error: 'ip_range_start deve ser menor ou igual a ip_range_end' });
    }
    const unit = new UnitMapping({ name, ip_range_start, ip_range_end });
    await unit.save();
    logger.info(`Unidade criada: ${name}`);
    res.status(201).json(unit);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Unidade com este nome já existe' });
    }
    logger.error(`Erro ao criar unidade: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor', details: err.message });
  }
});

// Listar unidades
app.get('/api/units', authenticate, async (req, res) => {
  try {
    const units = await UnitMapping.find().lean();
    logger.info(`Lista de unidades retornada: ${units.length} unidades`);
    res.status(200).json(units);
  } catch (err) {
    logger.error(`Erro ao obter unidades: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Atualizar unidade
app.put('/api/units/:name', authenticate, async (req, res) => {
  try {
    const { name, ip_range_start, ip_range_end } = req.body;
    const unit = await UnitMapping.findOneAndUpdate(
      { name: req.params.name },
      { name, ip_range_start, ip_range_end },
      { new: true }
    );
    if (!unit) {
      return res.status(404).json({ error: 'Unidade não encontrada' });
    }
    logger.info(`Unidade atualizada: ${name}`);
    res.status(200).json(unit);
  } catch (err) {
    logger.error(`Erro ao atualizar unidade: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Excluir unidade
app.delete('/api/units/:name', authenticate, async (req, res) => {
  try {
    const unit = await UnitMapping.findOneAndDelete({ name: req.params.name });
    if (!unit) {
      return res.status(404).json({ error: 'Unidade não encontrada' });
    }
    logger.info(`Unidade excluída: ${req.params.name}`);
    res.status(200).json({ message: `Unidade ${req.params.name} excluída com sucesso` });
  } catch (err) {
    logger.error(`Erro ao excluir unidade: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Criar mapeamento de BSSID
app.post('/api/bssid-mappings', authenticate, [
  body('mac_address_radio')
    .notEmpty()
    .matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/)
    .withMessage('mac_address_radio deve ser um MAC válido'),
  body('sector').notEmpty().withMessage('sector é obrigatório'),
  body('floor').notEmpty().withMessage('floor é obrigatório'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Erros de validação: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const { mac_address_radio, sector, floor } = req.body;
    const mapping = new BssidMapping({ mac_address_radio, sector, floor });
    await mapping.save();
    logger.info(`Mapeamento de BSSID criado: ${mac_address_radio}`);
    res.status(201).json(mapping);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'BSSID já mapeado' });
    }
    logger.error(`Erro ao criar mapeamento de BSSID: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Listar mapeamentos de BSSID
app.get('/api/bssid-mappings', authenticate, async (req, res) => {
  try {
    const mappings = await BssidMapping.find().lean();
    logger.info(`Lista de mapeamentos de BSSID retornada: ${mappings.length} mapeamentos`);
    res.status(200).json(mappings);
  } catch (err) {
    logger.error(`Erro ao obter mapeamentos de BSSID: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Atualizar mapeamento de BSSID
app.put('/api/bssid-mappings/:mac_address_radio', authenticate, async (req, res) => {
  try {
    const { sector, floor } = req.body;
    const mapping = await BssidMapping.findOneAndUpdate(
      { mac_address_radio: req.params.mac_address_radio },
      { sector, floor },
      { new: true }
    );
    if (!mapping) {
      return res.status(404).json({ error: 'Mapeamento de BSSID não encontrado' });
    }
    logger.info(`Mapeamento de BSSID atualizado: ${req.params.mac_address_radio}`);
    res.status(200).json(mapping);
  } catch (err) {
    logger.error(`Erro ao atualizar mapeamento de BSSID: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Excluir mapeamento de BSSID
app.delete('/api/bssid-mappings/:mac_address_radio', authenticate, async (req, res) => {
  try {
    const mapping = await BssidMapping.findOneAndDelete({ mac_address_radio: req.params.mac_address_radio });
    if (!mapping) {
      return res.status(404).json({ error: 'Mapeamento de BSSID não encontrado' });
    }
    logger.info(`Mapeamento de BSSID excluído: ${req.params.mac_address_radio}`);
    res.status(200).json({ message: `Mapeamento de BSSID ${req.params.mac_address_radio} excluído com sucesso` });
  } catch (err) {
    logger.error(`Erro ao excluir mapeamento de BSSID: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Iniciar servidor
app.listen(port, ip, () => {
  logger.info(`🚀 MDM Server rodando em http://${getLocalIPAddress()}:${port}`);
  logger.info(`📱 Provisionamento disponível em: http://${getLocalIPAddress()}:${port}/provision/{token}`);
  logger.info(`📊 Dashboard disponível em: http://${getLocalIPAddress()}:${port}/dashboard`);
});