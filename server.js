const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const winston = require('winston');
const os = require('os');
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
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
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
  maxPoolSize: 10, // Aumentar pool de conexões
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
  device_model: String,
  device_id: { type: String, unique: true, required: true },
  battery: Number,
  network: String,
  host: String,
  serial_number: String,
  imei: String,
  sector: String,
  floor: String,
  last_sync: String,
  secure_android_id: String,
  mac_address: String,
  ip_address: String,
  last_seen: { type: Date, default: Date.now },
});
const Device = mongoose.model('Device', DeviceSchema);

// Modelo de comando
const CommandSchema = new mongoose.Schema({
  device_id: { type: String, required: true },
  command: { type: String, required: true },
  packageName: String,
  apkUrl: String,
  status: { type: String, default: 'pending' },
  createdAt: { type: Date, default: Date.now },
});
const Command = mongoose.model('Command', CommandSchema);

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
      device = new Device(data);
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
      logger.warn(`Faltam campo obrigatório: device_id de ${req.ip}`);
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

    logger.info(`Heartbeat recebido: ${device_id}`);
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
    res.json(devices);
  } catch (err) {
    logger.error(`Erro ao obter dispositivos: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Obter comandos pendentes
app.get('/api/devices/commands', authenticate, async (req, res) => {
  try {
    const { device_id } = req.query;
    if (!device_id) {
      logger.warn('Faltam campo obrigatório: device_id');
      return res.status(400).json({ error: 'device_id é obrigatório' });
    }

    const commands = await Command.find({ device_id, status: 'pending' }).lean();
    if (commands.length > 0) {
      await Command.updateMany({ device_id, status: 'pending' }, { status: 'sent' });
      logger.info(`Comandos pendentes encontrados para ${device_id}: ${commands.length}`);
    }

    res.json(commands.map(cmd => ({
      id: cmd._id,
      command_type: cmd.command,
      parameters: { packageName: cmd.packageName, apkUrl: cmd.apkUrl }
    })));
  } catch (err) {
    logger.error(`Erro ao obter comandos: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Executar comandos
app.post('/api/executeCommand', authenticate, async (req, res) => {
  const { device_id, command, packageName, apkUrl } = req.body;
  try {
    if (!device_id || !command) {
      logger.warn('Faltam campos obrigatórios: device_id ou command');
      return res.status(400).json({ error: 'device_id e command são obrigatórios' });
    }

    await Command.create({ device_id, command, packageName, apkUrl });
    logger.info(`Comando "${command}" registrado para ${device_id}`);
    res.status(200).json({ message: `Comando ${command} registrado com sucesso` });
  } catch (err) {
    logger.error(`Erro ao processar comando: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Métricas do servidor
app.get('/api/server/status', authenticate, async (req, res) => {
  try {
    const cpus = os.cpus();
    const totalIdle = cpus.reduce((sum, cpu) => sum + cpu.times.idle, 0);
    const totalTick = cpus.reduce((sum, cpu) => sum + Object.values(cpu.times).reduce((t, v) => t + v, 0), 0);
    const cpuUsage = totalTick ? ((1 - totalIdle / totalTick) * 100).toFixed(1) : 0;

    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    const memoryUsage = ((1 - freeMemory / totalMemory) * 100).toFixed(1);

    const metrics = {
      cpu_usage: parseFloat(cpuUsage),
      memory_usage: parseFloat(memoryUsage),
      uptime: os.uptime(),
      device_count: await Device.countDocuments(),
    };

    logger.info(`Métricas do servidor retornadas: CPU ${metrics.cpu_usage}%, Memória ${metrics.memory_usage}%`);
    res.json(metrics);
  } catch (err) {
    logger.error(`Erro ao obter métricas do servidor: ${err.message}`);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para o painel web
app.get('/', (req, res) => {
  res.render('index', { token: process.env.AUTH_TOKEN });
});

// Iniciar servidor
app.listen(port, ip, () => {
  logger.info(`🚀 MDM Server rodando em http://${getLocalIPAddress()}:${port}`);
});