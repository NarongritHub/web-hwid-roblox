import os
import sqlite3
import requests
from flask import Flask, render_template_string, request, jsonify, session, redirect

app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET', 'roblox_python_secret_key_123')

# กำหนด Path ฐานข้อมูลให้อ่านจาก /data (ถ้าอยู่บนคลาวด์) หรือโฟลเดอร์ปัจจุบัน (ถ้าเทสในเครื่อง)
DATA_DIR = os.getenv('DATA_DIR', '.')
DB_PATH = os.path.join(DATA_DIR, 'database.db')

# สร้างตาราง SQLite อัตโนมัติเมื่อเริ่มรัน
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT NOT NULL,
            username TEXT NOT NULL,
            account_id TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            script_key TEXT UNIQUE NOT NULL,
            lua_script TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def is_authenticated():
    return 'user' in session

# ==========================================
# Discord OAuth2 Routes
# ==========================================
@app.route('/api/auth/discord')
def discord_auth():
    client_id = os.getenv('DISCORD_CLIENT_ID', '')
    redirect_uri = os.getenv('DISCORD_REDIRECT_URI', 'http://localhost:3000/api/auth/discord/callback')
    return redirect(f"https://discord.com/api/oauth2/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope=identify%20email")

@app.route('/api/auth/discord/callback')
def discord_callback():
    code = request.args.get('code')
    if not code:
        return "Missing Discord code", 400
    
    try:
        token_res = requests.post('https://discord.com/api/oauth2/token', data={
            'client_id': os.getenv('DISCORD_CLIENT_ID'),
            'client_secret': os.getenv('DISCORD_CLIENT_SECRET'),
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': os.getenv('DISCORD_REDIRECT_URI', 'http://localhost:3000/api/auth/discord/callback'),
        }, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        
        token_data = token_res.json()
        if 'access_token' not in token_data:
            return "Failed to get Discord token", 400

        user_res = requests.get('https://discord.com/api/users/@me', headers={
            'Authorization': f"{token_data['token_type']} {token_data['access_token']}"
        })
        user_data = user_res.json()

        avatar_url = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png" if user_data.get('avatar') else "https://cdn.discordapp.com/embed/avatars/0.png"
        
        session['user'] = {
            'id': user_data['id'],
            'username': user_data['username'],
            'avatar': avatar_url,
            'isAdmin': user_data['id'] == os.getenv('ADMIN_DISCORD_ID', '')
        }
        return redirect('/')
    except Exception as e:
        return f"Discord Authentication error: {str(e)}", 500

@app.route('/api/auth/me')
def auth_me():
    if 'user' in session:
        return jsonify({'loggedIn': True, 'user': session['user']})
    return jsonify({'loggedIn': False})

@app.route('/api/auth/logout')
def logout():
    session.clear()
    return jsonify({'success': True})

# ==========================================
# CRUD API Endpoints
# ==========================================
@app.route('/api/scripts', methods=['GET'])
def get_scripts():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scripts ORDER BY id DESC')
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({'success': True, 'data': rows})

@app.route('/api/scripts', methods=['POST'])
def create_script():
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.json
    if not all(k in data for k in ['username', 'account_id', 'password', 'script_key', 'lua_script']):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    from werkzeug.security import generate_password_hash
    password_hash = generate_password_hash(data['password'])

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO scripts (discord_id, username, account_id, password_hash, script_key, lua_script)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user']['id'], data['username'], data['account_id'], password_hash, data['script_key'], data['lua_script']))
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        return jsonify({'success': True, 'id': last_id})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'message': 'Script Key already exists'}), 400

@app.route('/api/scripts/<int:script_id>', methods=['PUT'])
def update_script(script_id):
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.json
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if data.get('password') and data['password'].strip() != '':
        from werkzeug.security import generate_password_hash
        password_hash = generate_password_hash(data['password'])
        cursor.execute('''
            UPDATE scripts SET username = ?, account_id = ?, script_key = ?, lua_script = ?, status = ?, password_hash = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (data['username'], data['account_id'], data['script_key'], data['lua_script'], data['status'], password_hash, script_id))
    else:
        cursor.execute('''
            UPDATE scripts SET username = ?, account_id = ?, script_key = ?, lua_script = ?, status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (data['username'], data['account_id'], data['script_key'], data['lua_script'], data['status'], script_id))

    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/scripts/<int:script_id>', methods=['DELETE'])
def delete_script(script_id):
    if not is_authenticated():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scripts WHERE id = ?', (script_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ==========================================
# Roblox Lua Executor Verification Endpoint
# ==========================================
@app.route('/api/verify-key', methods=['GET'])
def verify_key():
    key = request.args.get('key')
    if not key:
        return '-- [ERROR] Missing Key', 400
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT lua_script, status FROM scripts WHERE script_key = ?', (key,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return 'warn("[SECURITY] Invalid Key Provided!"); return;', 404
    if row['status'] != 'active':
        return 'warn("[SECURITY] Key has been revoked!"); return;', 403
    
    return row['lua_script'], 200, {'Content-Type': 'text/plain'}

# ==========================================
# Frontend Dashboard UI (Embedded Flask Template)
# ==========================================
@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="th" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Roblox Script & Key Management Dashboard (Python Flask)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: { colors: { dark: { 900: '#0b0f19', 800: '#111827', 700: '#1f2937', 600: '#374151' } } } }
        }
    </script>
</head>
<body class="bg-dark-900 text-gray-100 min-h-screen font-sans selection:bg-cyan-500 selection:text-black">
    <div id="app" class="max-w-7xl mx-auto px-4 py-8">
        <header class="flex flex-col md:flex-row justify-between items-center mb-8 bg-dark-800 p-6 rounded-2xl border border-dark-700 shadow-xl">
            <div class="flex items-center space-x-4 mb-4 md:mb-0">
                <div class="bg-gradient-to-tr from-cyan-500 to-purple-600 p-3 rounded-xl text-black font-black text-2xl shadow-lg">
                    <i class="fa-solid fa-shield-halved text-white"></i>
                </div>
                <div>
                    <h1 class="text-2xl font-bold tracking-tight text-white">Roblox Key & Script Manager (Python)</h1>
                    <p class="text-sm text-gray-400">Flask Backend & Discord SSO Dashboard</p>
                </div>
            </div>
            <div id="auth-section" class="flex items-center space-x-4">
                <span class="text-gray-400 text-sm">กำลังตรวจสอบสถานะ...</span>
            </div>
        </header>

        <div id="main-dashboard" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row justify-between gap-4 bg-dark-800 p-4 rounded-xl border border-dark-700">
                <div class="relative flex-1">
                    <i class="fa-solid fa-search absolute left-4 top-3.5 text-gray-400"></i>
                    <input type="text" id="search-input" placeholder="ค้นหา Username, Roblox ID หรือ Key..." 
                        class="w-full bg-dark-900 border border-dark-700 rounded-lg pl-11 pr-4 py-2.5 text-sm focus:outline-none focus:border-cyan-500 transition">
                </div>
                <button onclick="openModal()" class="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-semibold px-6 py-2.5 rounded-lg shadow-lg flex items-center justify-center space-x-2 transition">
                    <i class="fa-solid fa-plus"></i>
                    <span>เพิ่มข้อมูลใหม่</span>
                </button>
            </div>

            <div class="bg-dark-800 rounded-2xl border border-dark-700 shadow-xl overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr class="bg-dark-700 text-gray-300 text-xs uppercase tracking-wider border-b border-dark-600">
                                <th class="p-4">ID</th>
                                <th class="p-4">Username / Roblox ID</th>
                                <th class="p-4">Script Key</th>
                                <th class="p-4">Status</th>
                                <th class="p-4">Roblox Loadstring</th>
                                <th class="p-4 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="script-table-body" class="divide-y divide-dark-700 text-sm"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="login-prompt" class="hidden text-center py-20 bg-dark-800 rounded-2xl border border-dark-700 p-8 shadow-2xl">
            <div class="w-20 h-20 bg-indigo-600/20 text-indigo-400 rounded-full flex items-center justify-center mx-auto mb-6 text-3xl">
                <i class="fa-brands fa-discord"></i>
            </div>
            <h2 class="text-3xl font-bold mb-3 text-white">กรุณาล็อกอินเข้าสู่ระบบ</h2>
            <p class="text-gray-400 max-w-md mx-auto mb-8">ระบบรักษาความปลอดภัยจำกัดสิทธิ์เฉพาะผู้ใช้ผ่าน Discord OAuth2 เท่านั้น</p>
            <a href="/api/auth/discord" class="inline-flex items-center space-x-3 bg-[#5865F2] hover:bg-[#4752C4] text-white px-8 py-3.5 rounded-xl font-bold shadow-lg transition transform hover:-translate-y-0.5">
                <i class="fa-brands fa-discord text-xl"></i>
                <span>Login with Discord</span>
            </a>
        </div>
    </div>

    <!-- Modal -->
    <div id="script-modal" class="fixed inset-0 bg-black/70 backdrop-blur-sm hidden items-center justify-center p-4 z-50">
        <div class="bg-dark-800 border border-dark-700 w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden">
            <div class="flex justify-between items-center p-6 border-b border-dark-700 bg-dark-700/50">
                <h3 id="modal-title" class="text-lg font-bold text-white">เพิ่มข้อมูลสคริปต์ใหม่</h3>
                <button onclick="closeModal()" class="text-gray-400 hover:text-white"><i class="fa-solid fa-xmark text-xl"></i></button>
            </div>
            <form id="script-form" onsubmit="saveScript(event)" class="p-6 space-y-4">
                <input type="hidden" id="script-id">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-semibold text-gray-400 uppercase mb-1">Username</label>
                        <input type="text" id="form-username" required class="w-full bg-dark-900 border border-dark-700 rounded-lg p-3 text-sm focus:border-cyan-500 focus:outline-none">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-400 uppercase mb-1">Roblox / Account ID</label>
                        <input type="text" id="form-account-id" required class="w-full bg-dark-900 border border-dark-700 rounded-lg p-3 text-sm focus:border-cyan-500 focus:outline-none">
                    </div>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-semibold text-gray-400 uppercase mb-1">Password</label>
                        <input type="password" id="form-password" placeholder="เว้นว่างไว้หากไม่เปลี่ยน" class="w-full bg-dark-900 border border-dark-700 rounded-lg p-3 text-sm focus:border-cyan-500 focus:outline-none">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-400 uppercase mb-1">Script Key</label>
                        <div class="flex space-x-2">
                            <input type="text" id="form-key" required class="w-full bg-dark-900 border border-dark-700 rounded-lg p-3 text-sm focus:border-cyan-500 focus:outline-none">
                            <button type="button" onclick="generateKey()" class="bg-dark-700 hover:bg-dark-600 px-4 rounded-lg text-xs font-semibold">สุ่ม Key</button>
                        </div>
                    </div>
                </div>
                <div>
                    <label class="block text-xs font-semibold text-gray-400 uppercase mb-1">สถานะ Key</label>
                    <select id="form-status" class="w-full bg-dark-900 border border-dark-700 rounded-lg p-3 text-sm focus:border-cyan-500 focus:outline-none">
                        <option value="active">Active (ใช้งานได้)</option>
                        <option value="revoked">Revoked (ระงับการใช้งาน)</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs font-semibold text-gray-400 uppercase mb-1">Roblox Lua Script</label>
                    <textarea id="form-lua" rows="5" required placeholder="print('Hello Roblox!')" class="w-full bg-dark-900 border border-dark-700 rounded-lg p-3 font-mono text-xs focus:border-cyan-500 focus:outline-none"></textarea>
                </div>
                <div class="flex justify-end space-x-3 pt-4 border-t border-dark-700">
                    <button type="button" onclick="closeModal()" class="bg-dark-700 hover:bg-dark-600 px-5 py-2.5 rounded-lg text-sm font-semibold">ยกเลิก</button>
                    <button type="submit" class="bg-cyan-500 hover:bg-cyan-400 text-black px-6 py-2.5 rounded-lg text-sm font-bold shadow-lg">บันทึกข้อมูล</button>
                </div>
            </form>
        </div>
    </div>

<script>
        let allScripts = [];

        async function checkAuth() {
            try {
                const res = await fetch('/api/auth/me');
                const data = await res.json();
                if (data.loggedIn) {
                    document.getElementById('auth-section').innerHTML = `
                        <div class="flex items-center space-x-3 bg-dark-700/60 px-4 py-2 rounded-xl border border-dark-600">
                            <img src="${data.user.avatar}" class="w-9 h-9 rounded-full ring-2 ring-cyan-500">
                            <div>
                                <p class="text-sm font-bold text-white">${data.user.username}</p>
                                <p class="text-xs text-cyan-400">${data.user.isAdmin ? '👑 Administrator' : 'Verified User'}</p>
                            </div>
                            <button onclick="logout()" class="ml-4 text-red-400 hover:text-red-300 text-sm"><i class="fa-solid fa-right-from-bracket"></i></button>
                        </div>
                    `;
                    document.getElementById('main-dashboard').classList.remove('hidden');
                    document.getElementById('login-prompt').classList.add('hidden');
                    loadScripts();
                } else {
                    document.getElementById('auth-section').innerHTML = '';
                    document.getElementById('main-dashboard').classList.add('hidden');
                    document.getElementById('login-prompt').classList.remove('hidden');
                }
            } catch (err) { console.error(err); }
        }

        async function logout() {
            await fetch('/api/auth/logout');
            window.location.reload();
        }

        async function loadScripts() {
            const res = await fetch('/api/scripts');
            const result = await res.json();
            if (result.success) {
                allScripts = result.data;
                renderTable(allScripts);
            }
        }

        function renderTable(scripts) {
            const tbody = document.getElementById('script-table-body');
            tbody.innerHTML = '';
            if (scripts.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-center py-10 text-gray-500">ไม่พบข้อมูลในระบบ</td></tr>`;
                return;
            }
            const host = window.location.origin;
            scripts.forEach(s => {
                const loadstring = `loadstring(game:HttpGet("${host}/api/verify-key?key=${s.script_key}"))()`;
                const statusBadge = s.status === 'active' 
                    ? '<span class="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2.5 py-1 rounded-full text-xs font-semibold">Active</span>'
                    : '<span class="bg-red-500/10 text-red-400 border border-red-500/20 px-2.5 py-1 rounded-full text-xs font-semibold">Revoked</span>';

                // Escape string สำหรับใส่ใน onclick
                const escapedLoadstring = loadstring.replace(/'/g, "\\'").replace(/"/g, '&quot;');

                tbody.innerHTML += `
                    <tr class="hover:bg-dark-700/40 transition">
                        <td class="p-4 font-mono text-xs text-gray-400">#${s.id}</td>
                        <td class="p-4"><div class="font-bold text-white">${s.username}</div><div class="text-xs text-gray-400">ID: ${s.account_id}</div></td>
                        <td class="p-4 font-mono text-cyan-400 text-xs">${s.script_key}</td>
                        <td class="p-4">${statusBadge}</td>
                        <td class="p-4">
                            <div class="flex items-center space-x-2 bg-dark-900 px-3 py-1.5 rounded-lg border border-dark-700 max-w-xs">
                                <span class="truncate font-mono text-xs text-gray-300">${loadstring}</span>
                                <button onclick="copyText('${escapedLoadstring}')" class="text-cyan-400 hover:text-cyan-300 text-xs" title="คัดลอก Loadstring">
                                    <i class="fa-regular fa-copy"></i>
                                </button>
                            </div>
                        </td>
                        <td class="p-4 text-right space-x-2">
                            <button onclick="openModal(${s.id})" class="bg-dark-700 hover:bg-dark-600 text-gray-200 px-3 py-1.5 rounded-lg text-xs"><i class="fa-solid fa-pen"></i></button>
                            <button onclick="deleteScript(${s.id})" class="bg-red-500/10 hover:bg-red-500/20 text-red-400 px-3 py-1.5 rounded-lg text-xs"><i class="fa-solid fa-trash"></i></button>
                        </td>
                    </tr>
                `;
            });
        }

        // ฟังก์ชันคัดลอกที่รองรับทั้ง Clipboard API และ Fallback
        function copyText(text) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('คัดลอก Loadstring สำเร็จ!');
                }).catch(() => {
                    fallbackCopyText(text);
                });
            } else {
                fallbackCopyText(text);
            }
        }

        function fallbackCopyText(text) {
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                const successful = document.execCommand('copy');
                if (successful) {
                    alert('คัดลอก Loadstring สำเร็จ!');
                } else {
                    alert('ไม่สามารถคัดลอกได้');
                }
            } catch (err) {
                alert('เกิดข้อผิดพลาดในการคัดลอก');
            }
            document.body.removeChild(textArea);
        }

        function openModal(id = null) {
            document.getElementById('script-modal').classList.remove('hidden');
            document.getElementById('script-modal').classList.add('flex');
            if (!id) {
                document.getElementById('modal-title').innerText = 'เพิ่มข้อมูลสคริปต์ใหม่';
                document.getElementById('script-form').reset();
                document.getElementById('script-id').value = '';
                generateKey();
            } else {
                document.getElementById('modal-title').innerText = 'แก้ไขข้อมูลสคริปต์';
                const s = allScripts.find(item => item.id === id);
                if (s) {
                    document.getElementById('script-id').value = s.id;
                    document.getElementById('form-username').value = s.username;
                    document.getElementById('form-account-id').value = s.account_id;
                    document.getElementById('form-password').value = '';
                    document.getElementById('form-key').value = s.script_key;
                    document.getElementById('form-status').value = s.status;
                    document.getElementById('form-lua').value = s.lua_script;
                }
            }
        }

        function closeModal() {
            document.getElementById('script-modal').classList.add('hidden');
            document.getElementById('script-modal').classList.remove('flex');
        }

        function generateKey() {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let key = 'KEY_';
            for (let i = 0; i < 24; i++) key += chars.charAt(Math.floor(Math.random() * chars.length));
            document.getElementById('form-key').value = key;
        }

        async function saveScript(event) {
            event.preventDefault();
            const id = document.getElementById('script-id').value;
            const data = {
                username: document.getElementById('form-username').value,
                account_id: document.getElementById('form-account-id').value,
                password: document.getElementById('form-password').value,
                script_key: document.getElementById('form-key').value,
                status: document.getElementById('form-status').value,
                lua_script: document.getElementById('form-lua').value
            };
            const res = await fetch(id ? `/api/scripts/${id}` : '/api/scripts', {
                method: id ? 'PUT' : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await res.json();
            if (result.success) { closeModal(); loadScripts(); } else { alert(result.message); }
        }

        async function deleteScript(id) {
            if (!confirm('ยืนยันการลบ?')) return;
            const res = await fetch(`/api/scripts/${id}`, { method: 'DELETE' });
            const result = await res.json();
            if (result.success) loadScripts();
        }

        document.getElementById('search-input').addEventListener('input', (e) => {
            const q = e.target.value.toLowerCase();
            renderTable(allScripts.filter(s => s.username.toLowerCase().includes(q) || s.account_id.toLowerCase().includes(q) || s.script_key.toLowerCase().includes(q)));
        });

        checkAuth();
    </script>
</body>
</html>
    ''')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=False)