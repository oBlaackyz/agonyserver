const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const auth = require('basic-auth');

const app = express();
app.use(express.json());
app.use(cors());

// ==========================================
// CONFIGURAÇÃO DO PAINEL ADMIN
// MUDE ESTES DADOS PARA O SEU LOGIN!
// ==========================================
const ADMIN_USER = "admin"; 
const ADMIN_PASS = "Alves41."; // <--- MUDE ESTA SENHA!

// Middleware de Autenticação do Painel
const requireAdminAuth = (req, res, next) => {
    const user = auth(req);
    if (user && user.name === ADMIN_USER && user.pass === ADMIN_PASS) {
        return next();
    }
    res.set('WWW-Authenticate', 'Basic realm="Agony Admin"');
    res.status(401).send('Acesso negado ao painel.');
};

// Cria o banco de dados local (arquivo agony.db)
const dbPath = process.env.NODE_ENV === 'production' ? '/data/agony.db' : './agony.db';
const db = new sqlite3.Database(dbPath);

// Cria a tabela e insere as keys
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS licenses (
        key TEXT PRIMARY KEY,
        username TEXT,
        hwid TEXT,
        first_login INTEGER,
        last_login INTEGER,
        revoked INTEGER DEFAULT 0
    )`);

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

// ==========================================
// ROTAS DA API DO MOD (Minecraft)
// ==========================================
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

        if (row.hwid) {
            if (row.hwid === hwid && row.username === username) {
                db.run("UPDATE licenses SET last_login = ? WHERE key = ?", [now, key]);
                return res.status(200).json({ message: "Login autorizado" });
            } else {
                return res.status(403).json({ error: "Key em uso em outro dispositivo" });
            }
        }

        db.run("UPDATE licenses SET username = ?, hwid = ?, first_login = ?, last_login = ? WHERE key = ?",
            [username, hwid, now, now, key],
            (err) => {
                if (err) return res.status(500).json({ error: "Erro ao vincular key" });
                res.status(200).json({ message: "Key vinculada com sucesso" });
            }
        );
    });
});

// ==========================================
// ROTAS DA API DO PAINEL ADMIN
// ==========================================

// Listar todas as chaves
app.get('/api/admin/keys', requireAdminAuth, (req, res) => {
    db.all("SELECT * FROM licenses ORDER BY key ASC", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Resetar Key (desvincular do PC e do usuário)
app.post('/api/admin/reset', requireAdminAuth, (req, res) => {
    const { key } = req.body;
    db.run("UPDATE licenses SET username = NULL, hwid = NULL, first_login = NULL, last_login = NULL WHERE key = ?", [key], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Key resetada com sucesso" });
    });
});

// Revogar Key (bloquear de vez)
app.post('/api/admin/revoke', requireAdminAuth, (req, res) => {
    const { key, revoked } = req.body; // revoked = true ou false
    db.run("UPDATE licenses SET revoked = ? WHERE key = ?", [revoked ? 1 : 0, key], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Status de revogação atualizado" });
    });
});

// ==========================================
// FRONTEND DO PAINEL ADMIN (HTML/CSS/JS)
// ==========================================
app.get('/admin', requireAdminAuth, (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Agony - Painel Admin</title>
    <style>
        body { background-color: #0f0507; color: #fee2e2; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; }
        h1 { color: #dc2626; text-align: center; text-transform: uppercase; letter-spacing: 2px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background-color: #190a0d; box-shadow: 0 0 10px rgba(220, 38, 38, 0.2); }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #3a1217; }
        th { background-color: #7f1d1d; color: white; }
        tr:hover { background-color: #241114; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-free { background-color: #4ade80; color: #000; }
        .badge-used { background-color: #fbbf24; color: #000; }
        .badge-revoked { background-color: #ef4444; color: #fff; }
        button { padding: 6px 12px; cursor: pointer; border: none; border-radius: 4px; font-weight: bold; margin-right: 5px; }
        .btn-reset { background-color: #3b82f6; color: white; }
        .btn-revoke { background-color: #dc2626; color: white; }
        .btn-unrevoke { background-color: #4ade80; color: #000; }
        button:hover { opacity: 0.8; }
        .hwid { font-family: monospace; font-size: 12px; color: #9c7b7e; }
    </style>
</head>
<body>
    <h1>Painel de Licenças - Agony</h1>
    <table>
        <thead>
            <tr>
                <th>Key</th>
                <th>Usuário</th>
                <th>HWID (PC)</th>
                <th>Status</th>
                <th>Ações</th>
            </tr>
        </thead>
        <tbody id="table-body">
            <tr><td colspan="5" style="text-align:center;">Carregando...</td></tr>
        </tbody>
    </table>

    <script>
        async function loadKeys() {
            const res = await fetch('/api/admin/keys');
            const keys = await res.json();
            const tbody = document.getElementById('table-body');
            tbody.innerHTML = '';

            keys.forEach(k => {
                const tr = document.createElement('tr');
                
                let status = '';
                if (k.revoked === 1) {
                    status = '<span class="badge badge-revoked">REVOGADA</span>';
                } else if (k.hwid) {
                    status = '<span class="badge badge-used">EM USO</span>';
                } else {
                    status = '<span class="badge badge-free">LIVRE</span>';
                }

                tr.innerHTML = \`
                    <td><strong>\${k.key}</strong></td>
                    <td>\${k.username || '-'}</td>
                    <td class="hwid">\${k.hwid ? k.hwid.substring(0, 15) + '...' : '-'}</td>
                    <td>\${status}</td>
                    <td>
                        <button class="btn-reset" onclick="resetKey('\${k.key}')">Resetar</button>
                        \${k.revoked === 1 
                            ? \`<button class="btn-unrevoke" onclick="toggleRevoke('\${k.key}', false)">Reativar</button>\`
                            : \`<button class="btn-revoke" onclick="toggleRevoke('\${k.key}', true)">Revogar</button>\`
                        }
                    </td>
                \`;
                tbody.appendChild(tr);
            });
        }

        async function resetKey(key) {
            if (!confirm('Tem certeza que deseja desvincular a key ' + key + '? Ela ficará livre para outro PC.')) return;
            await fetch('/api/admin/reset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key })
            });
            loadKeys();
        }

        async function toggleRevoke(key, revoked) {
            await fetch('/api/admin/revoke', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key, revoked })
            });
            loadKeys();
        }

        // Carrega as keys ao abrir a página
        loadKeys();
    </script>
</body>
</html>
    `);
});

// Inicia o servidor
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Servidor Agony rodando na porta ${PORT}`);
});