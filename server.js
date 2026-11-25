const path = require('path');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Cria o banco de dados local (arquivo agony.db)
// O Railway monta o disco persistente na pasta /data. É para lá que o banco deve ir.
const dbPath = process.env.NODE_ENV === 'production' ? '/data/agony.db' : './agony.db';
const db = new sqlite3.Database(dbPath);

// Cria a tabela se não existir
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS licenses (
        key TEXT PRIMARY KEY,
        username TEXT,
        hwid TEXT,
        first_login INTEGER,
        last_login INTEGER,
        revoked INTEGER DEFAULT 0
    )`);

    // Insere as 20 keys (só insere se não existirem)
    const keys = [
        "AGONY-9X4L-P2Q8-7V1M", "AGONY-3T7W-K5B9-0J4N", "AGONY-6R1Y-H8C2-4F7G",
        "AGONY-2D5F-A9Z3-8B1Q", "AGONY-7M3K-4N6W-2E9R", "AGONY-1P8S-6T4U-3H5J",
        "AGONY-5G7D-1L9O-6C2V", "AGONY-4H2J-8R5Y-1W3Z", "AGONY-8Z1C-3M7B-9K4X",
        "AGONY-3V6N-5Q1F-2L8P", "AGONY-9W2E-7R4T-5Y1U", "AGONY-1K5B-9D2G-8F3M",
        "AGONY-6Q4A-2S7J-4V8C", "AGONY-2M9F-6H1X-7Z5N", "AGONY-7T3R-8L5K-1B4Q",
        "AGONY-5J1U-4Y6W-9E2A", "AGONY-4C8V-1N3P-6T7R", "AGONY-8F2X-9Q5M-3K1J",
        "AGONY-3A7K-7W2Z-5U6H", "AGONY-1E4Q-5B8C-4D9L"
    ];
    
    keys.forEach(k => {
        db.run("INSERT OR IGNORE INTO licenses (key) VALUES (?)", [k]);
    });
});

// Rota de Login
app.post('/api/login', (req, res) => {
    const { username, key, hwid } = req.body;
    
    if (!username || !key || !hwid) {
        return res.status(400).json({ error: "Dados incompletos" });
    }

    const now = Date.now();

    db.get("SELECT * FROM licenses WHERE key = ?", [key], (err, row) => {
        if (err) return res.status(500).json({ error: "Erro no banco" });
        if (!row) return res.status(401).json({ error: "Key inválida" });
        if (row.revoked === 1) return res.status(403).json({ error: "Key revogada" });

        // Se a key já tem dono
        if (row.hwid) {
            // Se for o mesmo usuário e mesmo HWID, libera
            if (row.hwid === hwid && row.username === username) {
                db.run("UPDATE licenses SET last_login = ? WHERE key = ?", [now, key]);
                return res.status(200).json({ message: "Login autorizado" });
            } else {
                // Se for outro PC ou outro usuário, bloqueia
                return res.status(403).json({ error: "Key em uso em outro dispositivo" });
            }
        }

        // Se a key está livre (primeiro login), vincula ao HWID
        db.run("UPDATE licenses SET username = ?, hwid = ?, first_login = ?, last_login = ? WHERE key = ?",
            [username, hwid, now, now, key],
            (err) => {
                if (err) return res.status(500).json({ error: "Erro ao vincular key" });
                res.status(200).json({ message: "Key vinculada com sucesso" });
            }
        );
    });
});

// Inicia o servidor na porta 8080
app.listen(8080, () => {
    console.log('Servidor Agony rodando na porta 8080');
});