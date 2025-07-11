const WebSocket = require("ws");
const http = require("http");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const ADMIN_TOKENS = new Set((process.env.ADMIN_TOKENS || "").split(","));

class UserRole {
  static ADMIN = "admin";
  static SLAVE = "slave";
}

class ClientSession {
  constructor(websocket, username, role, connectionId, autoAssigned = false) {
    this.websocket = websocket;
    this.username = username;
    this.role = role;
    this.connectionId = connectionId;
    this.autoAssigned = autoAssigned;
    this.connectedAt = Date.now();
  }
}

class SmartUserManager {
  constructor() {
    this.slaveCounter = 0;
    this.reservedUsernames = new Set(["admin", "root", "system", "server"]);
  }

  generateSlaveUsername() {
    return `Slav${++this.slaveCounter}`;
  }

  validateAdminToken(token) {
    return ADMIN_TOKENS.has(token);
  }

  isUsernameReserved(username) {
    return this.reservedUsernames.has(username.toLowerCase());
  }
}

class ConnectionPool {
  constructor() {
    this.clients = new Map();
    this.websocketMap = new WeakMap();
    this.connectionCounter = 0;
  }

  addClient(websocket, session) {
    this.clients.set(session.username, session);
    this.websocketMap.set(websocket, session);
    this.connectionCounter++;
  }

  removeClient(websocket) {
    const session = this.websocketMap.get(websocket);
    if (session) {
      this.clients.delete(session.username);
      this.websocketMap.delete(websocket);
    }
    return session;
  }

  getSession(websocket) {
    return this.websocketMap.get(websocket);
  }

  getClientByUsername(username) {
    return this.clients.get(username);
  }

  getAllSlaves() {
    return Array.from(this.clients.values()).filter(s => s.role === UserRole.SLAVE);
  }

  getAllUsernames() {
    return Array.from(this.clients.keys());
  }

  getStats() {
    const slaves = this.getAllSlaves();
    const admins = Array.from(this.clients.values()).filter(s => s.role === UserRole.ADMIN);
    
    return {
      totalConnections: this.clients.size,
      slaves: slaves.length,
      admins: admins.length,
      autoAssigned: slaves.filter(s => s.autoAssigned).length
    };
  }
}

class MessageRouter {
  constructor(pool, userManager) {
    this.pool = pool;
    this.userManager = userManager;
    this.messageHandlers = {
      "/auth": this.handleAuth.bind(this),
      "/list": this.handleList.bind(this),
      "/msg": this.handlePrivateMessage.bind(this),
      "/kick": this.handleKick.bind(this),
      "/stats": this.handleStats.bind(this)
    };
  }

  async routeMessage(websocket, message) {
    const session = this.pool.getSession(websocket);
    if (!session) {
      websocket.send("X Not authenticated");
      return;
    }

    message = message.trim();

    for (const [command, handler] of Object.entries(this.messageHandlers)) {
      if (message.startsWith(command)) {
        await handler(session, message);
        return;
      }
    }

    await this.handleBroadcast(session, message);
  }

  async handleAuth(session, message) {
    if (session.role === UserRole.ADMIN) {
      session.websocket.send("+ Already authenticated as admin");
      return;
    }

    const parts = message.split(" ");
    if (parts.length < 2) {
      session.websocket.send("X Usage: /auth <token>");
      return;
    }

    const token = parts[1];
    if (this.userManager.validateAdminToken(token)) {
      session.role = UserRole.ADMIN;
      session.websocket.send("+ Admin privileges granted");
    } else {
      session.websocket.send("X Invalid admin token");
    }
  }

  async handleList(session, message) {
    let usernames;
    if (session.role !== UserRole.ADMIN) {
      const slaves = this.pool.getAllSlaves();
      usernames = slaves.map(s => s.username);
    } else {
      usernames = this.pool.getAllUsernames();
    }

    const userList = usernames.length > 0 ? usernames.join(", ") : "None";
    session.websocket.send(`[Users]: ${userList}`);
  }

  async handlePrivateMessage(session, message) {
    const parts = message.split(" ");
    if (parts.length < 3) {
      session.websocket.send("X Usage: /msg <username> <message>");
      return;
    }

    const targetUsername = parts[1];
    const msgContent = parts.slice(2).join(" ");
    const targetSession = this.pool.getClientByUsername(targetUsername);

    if (!targetSession) {
      session.websocket.send(`X User ${targetUsername} not found`);
      return;
    }

    if (targetSession.websocket.readyState === WebSocket.OPEN) {
      targetSession.websocket.send(`[${session.username}] ${msgContent}`);
    }
  }

  async handleKick(session, message) {
    if (session.role !== UserRole.ADMIN) {
      session.websocket.send("X Admin privileges required");
      return;
    }

    const parts = message.split(" ");
    if (parts.length < 2) {
      session.websocket.send("X Usage: /kick <username>");
      return;
    }

    const targetUsername = parts[1];
    const targetSession = this.pool.getClientByUsername(targetUsername);

    if (!targetSession) {
      session.websocket.send(`X User ${targetUsername} not found`);
      return;
    }

    if (targetSession.role === UserRole.ADMIN) {
      session.websocket.send("X Cannot kick admin");
      return;
    }

    targetSession.websocket.send("X Kicked by admin");
    targetSession.websocket.close();
    session.websocket.send(`+ Kicked ${targetUsername}`);
  }

  async handleStats(session, message) {
    if (session.role !== UserRole.ADMIN) {
      session.websocket.send("X Admin privileges required");
      return;
    }

    const stats = this.pool.getStats();
    session.websocket.send(`[Stats]: ${JSON.stringify(stats)}`);
  }

  async handleBroadcast(session, message) {
    const broadcastMsg = `${session.username}: ${message}`;
    
    for (const clientSession of this.pool.clients.values()) {
      if (clientSession.websocket !== session.websocket && 
          clientSession.websocket.readyState === WebSocket.OPEN) {
        try {
          clientSession.websocket.send(broadcastMsg);
        } catch (error) {
          console.error(`! Error broadcasting to ${clientSession.username}:`, error.message);
        }
      }
    }
  }
}

class WebSocketServer {
  constructor() {
    this.pool = new ConnectionPool();
    this.userManager = new SmartUserManager();
    this.router = new MessageRouter(this.pool, this.userManager);
    this.server = http.createServer(this.handleHttpRequest.bind(this));
    this.wss = new WebSocket.Server({ server: this.server });
    
    this.wss.on("connection", this.handleConnection.bind(this));
  }

  handleHttpRequest(req, res) {
    if (req.url === '/health') {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("OK");
      return;
    }
    
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    });
    
    const response = {
      status: "active",
      protocol: "smart-websocket",
      timestamp: new Date().toISOString(),
      stats: this.pool.getStats()
    };
    
    res.end(JSON.stringify(response));
  }

  async authenticateConnection(websocket) {
    const username = this.userManager.generateSlaveUsername();
    const connectionId = `conn_${crypto.randomBytes(4).toString("hex")}`;
    
    const session = new ClientSession(
      websocket,
      username,
      UserRole.SLAVE,
      connectionId,
      true
    );
    
    this.pool.addClient(websocket, session);
    websocket.send(`+ Auto-assigned: ${username}`);
    console.log(`+ ${username} connected (${connectionId})`);
    
    return session;
  }

  async handleConnection(websocket) {
    const session = await this.authenticateConnection(websocket);
    
    websocket.on("message", async (message) => {
      try {
        await this.router.routeMessage(websocket, message.toString());
      } catch (error) {
        console.error(`! Error handling message from ${session.username}:`, error.message);
        websocket.send("X Internal server error");
      }
    });

    websocket.on("close", () => {
      const removedSession = this.pool.removeClient(websocket);
      if (removedSession) {
        console.log(`- ${removedSession.username} disconnected`);
      }
    });

    websocket.on("error", (error) => {
      console.error(`! WebSocket error for ${session.username}:`, error.message);
    });
  }

  start() {
    this.server.listen(PORT, "0.0.0.0", () => {
      console.log(`* Smart WebSocket server running on 0.0.0.0:${PORT}`);
      console.log(`* Admin tokens configured: ${ADMIN_TOKENS.size}`);
      console.log(`* Health check: http://localhost:${PORT}/health`);
    });
  }
}

const server = new WebSocketServer();
server.start();
