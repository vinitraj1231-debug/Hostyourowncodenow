# ==================== LOGIN PAGE ====================
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost — {{ title }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Plus+Jakarta+Sans:wght@700;800&display=swap" rel="stylesheet">
    <style>
        :root { --accent: #ffffff; --bg: #000000; --card: #0a0a0a; --border: #1a1a1a; }
        body { font-family: 'Inter', sans-serif; background-color: var(--bg); color: #fff; }
        .font-heading { font-family: 'Plus Jakarta Sans', sans-serif; }
        .glass { background: var(--card); border: 1px solid var(--border); }
        .btn-premium { background: #fff; color: #000; font-weight: 700; transition: all 0.3s ease; }
        .btn-premium:hover { background: #e0e0e0; transform: translateY(-1px); }
        .input-field { background: #050505; border: 1px solid var(--border); color: #fff; }
        .input-field:focus { border-color: #444; outline: none; }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-6">
    <div class="max-w-md w-full">
        <div class="glass rounded-2xl p-10 shadow-2xl">
            <div class="text-center mb-10">
                <div class="inline-flex items-center justify-center w-12 h-12 border border-white/10 mb-6">
                    <i class="fas fa-cube text-white text-xl"></i>
                </div>
                <h1 class="text-2xl font-heading font-extrabold tracking-tighter uppercase mb-1">EliteHost</h1>
                <p class="text-[10px] text-gray-500 uppercase tracking-[0.3em] font-bold">{{ subtitle }}</p>
            </div>

            {% if error %}
            <div class="bg-white/5 border border-white/10 rounded-lg p-4 mb-6 text-xs text-white/80 flex items-center gap-3">
                <i class="fas fa-exclamation-circle"></i>{{ error }}
            </div>
            {% endif %}
            {% if success %}
            <div class="bg-white/5 border border-white/10 rounded-lg p-4 mb-6 text-xs text-white/80 flex items-center gap-3">
                <i class="fas fa-check-circle"></i>{{ success }}
            </div>
            {% endif %}

            <form method="POST" action="{{ action }}" class="space-y-6">
                <div>
                    <label class="block text-[10px] font-bold uppercase tracking-widest text-gray-500 mb-2">Access Email</label>
                    <input type="email" name="email" required class="input-field w-full px-5 py-4 rounded-xl text-sm" placeholder="client@elitehost.cloud">
                </div>
                <div>
                    <label class="block text-[10px] font-bold uppercase tracking-widest text-gray-500 mb-2">Security Key</label>
                    <input type="password" name="password" required class="input-field w-full px-5 py-4 rounded-xl text-sm" placeholder="••••••••">
                </div>
                <button type="submit" class="btn-premium w-full py-5 rounded-xl text-[11px] uppercase tracking-widest">
                    {{ button_text }}
                </button>
            </form>

            <p class="text-center mt-10 text-[10px] text-gray-500 tracking-wide uppercase">
                {{ toggle_text }} <a href="{{ toggle_link }}" class="text-white font-bold ml-1">{{ toggle_action }}</a>
            </p>
        </div>
    </div>
</body>
</html>"""

# ==================== LANDING PAGE ====================
LANDING_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost — Next Gen Cloud Control</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@700;800&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #000000; --card: #080808; --border: #111111; }
        body { font-family: 'Inter', sans-serif; background-color: var(--bg); color: #fff; scroll-behavior: smooth; }
        .font-heading { font-family: 'Plus Jakarta Sans', sans-serif; }
        .nav-glass { background: rgba(0,0,0,0.8); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border); }
        .btn-white { background: #fff; color: #000; font-weight: 700; transition: all 0.3s; }
        .btn-white:hover { background: #ccc; }
        .btn-outline { border: 1px solid var(--border); background: transparent; color: #fff; transition: all 0.3s; }
        .btn-outline:hover { background: #111; border-color: #333; }
        .card { background: var(--card); border: 1px solid var(--border); transition: transform 0.3s; }
        .card:hover { border-color: #222; transform: translateY(-5px); }
        .hero-gradient { background: radial-gradient(circle at 50% 50%, #111 0%, #000 70%); }
    </style>
</head>
<body>
    <nav class="fixed top-0 w-full z-50 nav-glass py-6">
        <div class="max-w-7xl mx-auto px-8 flex justify-between items-center">
            <div class="flex items-center gap-2">
                <div class="w-8 h-8 border border-white flex items-center justify-center font-bold">E</div>
                <span class="text-xl font-heading font-extrabold tracking-tighter uppercase">EliteHost</span>
            </div>
            <div class="hidden md:flex gap-10 text-[10px] font-bold uppercase tracking-widest text-gray-400">
                <a href="#features" class="hover:text-white">Technology</a>
                <a href="#pricing" class="hover:text-white">Investment</a>
                <a href="/login" class="hover:text-white">Client Portal</a>
            </div>
            <a href="/register" class="btn-white px-6 py-2.5 rounded-full text-[10px] uppercase tracking-widest">Request Access</a>
        </div>
    </nav>

    <header class="min-h-screen flex items-center justify-center pt-20 hero-gradient">
        <div class="text-center max-w-4xl px-8">
            <div class="mb-6 inline-block border border-white/10 px-4 py-1.5 rounded-full">
                <span class="text-[9px] font-bold uppercase tracking-[0.3em] text-gray-500">Version 2.0 Architectural Excellence</span>
            </div>
            <h1 class="text-6xl md:text-8xl font-heading font-extrabold mb-8 tracking-tighter leading-none">
                CLOUD DEPLOYMENT <br><span class="text-gray-500">REDEFINED.</span>
            </h1>
            <p class="text-lg text-gray-400 mb-12 max-w-2xl mx-auto font-light leading-relaxed">
                EliteHost provides an ultra-fast, minimalist infrastructure for modern applications. Secure, containerized, and purely black & white.
            </p>
            <div class="flex flex-col sm:flex-row justify-center gap-6">
                <a href="/register" class="btn-white px-10 py-5 rounded-xl text-[11px] uppercase tracking-widest">Start Deploying</a>
                <a href="#features" class="btn-outline px-10 py-5 rounded-xl text-[11px] uppercase tracking-widest">Explore System</a>
            </div>
        </div>
    </header>

    <section id="features" class="py-32 border-y border-white/5">
        <div class="max-w-7xl mx-auto px-8">
            <div class="grid md:grid-cols-3 gap-12">
                <div class="card p-10 rounded-2xl">
                    <i class="fas fa-bolt text-2xl mb-8"></i>
                    <h3 class="text-xl font-heading font-bold mb-4 uppercase">Instant Manifest</h3>
                    <p class="text-gray-500 text-sm leading-relaxed">From raw code to a live endpoint in under 30 seconds. No complex config, just pure execution.</p>
                </div>
                <div class="card p-10 rounded-2xl">
                    <i class="fas fa-brain text-2xl mb-8"></i>
                    <h3 class="text-xl font-heading font-bold mb-4 uppercase">Neural Assistant</h3>
                    <p class="text-gray-500 text-sm leading-relaxed">Our built-in AI assistant helps you debug, optimize, and generate enterprise-grade code natively.</p>
                </div>
                <div class="card p-10 rounded-2xl">
                    <i class="fas fa-shield-alt text-2xl mb-8"></i>
                    <h3 class="text-xl font-heading font-bold mb-4 uppercase">Encrypted Core</h3>
                    <p class="text-gray-500 text-sm leading-relaxed">Every process runs in a cryptographically isolated container with granular permission control.</p>
                </div>
            </div>
        </div>
    </section>

    <section id="pricing" class="py-32">
        <div class="max-w-7xl mx-auto px-8">
            <div class="text-center mb-24">
                <h2 class="text-4xl font-heading font-extrabold uppercase mb-4">Investment Tiers</h2>
                <p class="text-gray-500 uppercase tracking-widest text-[10px] font-bold">Scalable Credit Infrastructure</p>
            </div>
            <div class="grid md:grid-cols-3 gap-8">
                <div class="card p-12 rounded-3xl">
                    <h4 class="text-[10px] font-bold uppercase tracking-widest text-gray-500 mb-8">Base Tier</h4>
                    <div class="text-4xl font-heading font-bold mb-8">₹50 <span class="text-xs text-gray-600 font-normal">/ 10 CR</span></div>
                    <ul class="space-y-4 mb-12 text-sm text-gray-400">
                        <li><i class="fas fa-check mr-2"></i> GitHub Sync</li>
                        <li><i class="fas fa-check mr-2"></i> AI Debugging</li>
                        <li><i class="fas fa-check mr-2"></i> Standard Support</li>
                    </ul>
                    <a href="/register" class="btn-outline w-full block text-center py-4 rounded-xl text-[10px] font-bold uppercase tracking-widest">Select Plan</a>
                </div>
                <div class="card p-12 rounded-3xl border-white/40 transform scale-105">
                    <h4 class="text-[10px] font-bold uppercase tracking-widest text-white mb-8">Professional</h4>
                    <div class="text-4xl font-heading font-bold mb-8">₹399 <span class="text-xs text-gray-600 font-normal">/ 99 CR</span></div>
                    <ul class="space-y-4 mb-12 text-sm text-white/80">
                        <li><i class="fas fa-check mr-2"></i> All Base Features</li>
                        <li><i class="fas fa-check mr-2"></i> Priority Deployment</li>
                        <li><i class="fas fa-check mr-2"></i> Advanced AI Context</li>
                        <li><i class="fas fa-check mr-2"></i> 24/7 Priority Access</li>
                    </ul>
                    <a href="/register" class="btn-white w-full block text-center py-4 rounded-xl text-[10px] font-bold uppercase tracking-widest">Select Plan</a>
                </div>
                <div class="card p-12 rounded-3xl">
                    <h4 class="text-[10px] font-bold uppercase tracking-widest text-gray-500 mb-8">Custom</h4>
                    <div class="text-4xl font-heading font-bold mb-8">Bespoke</div>
                    <p class="text-gray-500 text-sm mb-12">For large scale enterprise needs and custom credit packages.</p>
                    <a href="https://t.me/zolvid" class="btn-outline w-full block text-center py-4 rounded-xl text-[10px] font-bold uppercase tracking-widest">Contact Support</a>
                </div>
            </div>
        </div>
    </section>

    <footer class="py-16 border-t border-white/5">
        <div class="max-w-7xl mx-auto px-8 flex flex-col md:flex-row justify-between items-center gap-8">
            <div class="flex items-center gap-2">
                <div class="w-6 h-6 border border-white flex items-center justify-center font-bold text-xs">E</div>
                <span class="text-sm font-heading font-extrabold uppercase">EliteHost</span>
            </div>
            <div class="text-[10px] text-gray-600 font-bold uppercase tracking-widest">© 2025 ELITEHOST CLOUD. ALL RIGHTS RESERVED.</div>
            <div class="flex gap-6 text-gray-400">
                <a href="#" class="hover:text-white"><i class="fab fa-github"></i></a>
                <a href="#" class="hover:text-white"><i class="fab fa-twitter"></i></a>
                <a href="https://t.me/zolvid" class="hover:text-white"><i class="fab fa-telegram"></i></a>
            </div>
        </div>
    </footer>
</body>
</html>"""

# ==================== DASHBOARD PAGE ====================
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost — Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@700;800&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #000000; --card: #0a0a0a; --border: #1a1a1a; --text-muted: #666; }
        body { font-family: 'Inter', sans-serif; background: var(--bg); color: #fff; }
        .font-heading { font-family: 'Plus Jakarta Sans', sans-serif; }
        .sidebar { background: var(--bg); border-right: 1px solid var(--border); }
        .glass { background: var(--card); border: 1px solid var(--border); }
        .btn-white { background: #fff; color: #000; font-weight: 700; }
        .btn-white:hover { background: #e0e0e0; }
        .btn-outline { border: 1px solid var(--border); background: transparent; color: #fff; }
        .btn-outline:hover { background: #111; }
        .status-pill { padding: 4px 12px; border-radius: 100px; font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; }
        .status-running { background: #fff; color: #000; }
        .status-failed { background: #331111; color: #ff4444; border: 1px solid #552222; }
        .status-stopped { background: #111; color: #666; border: 1px solid #222; }
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #333; border-radius: 10px; }
    </style>
</head>
<body x-data="dashApp()">
    <!-- Sidebar -->
    <aside class="fixed inset-y-0 left-0 w-64 sidebar hidden md:flex flex-col p-8">
        <div class="flex items-center gap-3 mb-12">
            <div class="w-8 h-8 border border-white flex items-center justify-center font-bold">E</div>
            <span class="font-heading font-extrabold uppercase tracking-tighter text-lg">EliteHost</span>
        </div>

        <nav class="flex-1 space-y-2">
            <template x-for="item in navItems" :key="item.id">
                <button @click="navigate(item.id)"
                        :class="currentPage === item.id ? 'bg-white text-black' : 'text-gray-500 hover:text-white'"
                        class="w-full flex items-center gap-4 px-4 py-3.5 rounded-xl transition-all text-[11px] font-bold uppercase tracking-widest">
                    <i :class="item.icon" class="w-4"></i>
                    <span x-text="item.label"></span>
                </button>
            </template>
        </nav>

        <div class="pt-8 border-t border-white/5">
            <div class="glass p-5 rounded-2xl mb-4">
                <p class="text-[9px] font-bold text-gray-500 uppercase tracking-widest mb-2">Wallet Balance</p>
                <div class="text-2xl font-heading font-extrabold tracking-tighter" x-text="credits === Infinity ? 'UNLIMITED' : parseFloat(credits).toFixed(2)"></div>
            </div>
            <button @click="logout()" class="w-full text-left px-4 py-2 text-[10px] font-bold uppercase text-gray-600 hover:text-white transition-colors">Terminate Session</button>
        </div>
    </aside>

    <!-- Main Content -->
    <main class="md:ml-64 min-h-screen p-8 md:p-12">
        <div class="max-w-6xl mx-auto">

            <!-- OVERVIEW -->
            <div x-show="currentPage==='overview'">
                <div class="flex justify-between items-end mb-12">
                    <div>
                        <h1 class="text-4xl font-heading font-extrabold uppercase tracking-tighter">Command Center</h1>
                        <p class="text-gray-500 text-[10px] font-bold uppercase tracking-widest mt-2">Active Infrastructure Telemetry</p>
                    </div>
                    <div class="flex gap-4">
                        <div x-show="trial && trial.status==='active'" class="bg-white/5 border border-white/10 px-6 py-3 rounded-2xl flex items-center gap-4">
                            <span class="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Trial Ends</span>
                            <span class="font-mono text-xs font-bold" x-text="trialCountdown"></span>
                        </div>
                        <button @click="navigate('new-deploy')" class="btn-white px-8 py-3.5 rounded-xl text-[10px] uppercase tracking-widest">Initial Manifest</button>
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
                    <div class="glass p-8 rounded-3xl">
                        <p class="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-4">Deployments</p>
                        <div class="text-4xl font-heading font-extrabold" x-text="stats.total"></div>
                    </div>
                    <div class="glass p-8 rounded-3xl">
                        <p class="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-4">Active</p>
                        <div class="text-4xl font-heading font-extrabold" x-text="stats.running"></div>
                    </div>
                    <div class="glass p-8 rounded-3xl">
                        <p class="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-4">Trial State</p>
                        <div class="text-xl font-heading font-extrabold uppercase" x-text="trial?.status || 'N/A'"></div>
                    </div>
                    <div class="glass p-8 rounded-3xl">
                        <p class="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-4">Affiliate Earnings</p>
                        <div class="text-4xl font-heading font-extrabold">₹<span x-text="wallet?.total_earned || 0"></span></div>
                    </div>
                </div>

                <div class="glass rounded-[32px] overflow-hidden">
                    <div class="p-8 border-b border-white/5 flex justify-between items-center">
                        <h2 class="font-heading font-bold uppercase tracking-widest text-xs">Recent Activity</h2>
                        <button @click="navigate('deployments')" class="text-[10px] font-bold text-gray-500 uppercase hover:text-white">View Full Registry</button>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left">
                            <thead class="text-[9px] font-bold uppercase tracking-widest text-gray-600 bg-white/[0.02]">
                                <tr>
                                    <th class="px-8 py-4">Artifact</th>
                                    <th class="px-8 py-4">Environment</th>
                                    <th class="px-8 py-4">Identity</th>
                                    <th class="px-8 py-4">State</th>
                                    <th class="px-8 py-4">Endpoint</th>
                                </tr>
                            </thead>
                            <tbody class="text-xs divide-y divide-white/5">
                                <template x-for="d in deployments.slice(0,5)" :key="d.id">
                                    <tr class="hover:bg-white/[0.01] cursor-pointer" @click="viewDeployment(d.id)">
                                        <td class="px-8 py-6 font-bold uppercase" x-text="d.name"></td>
                                        <td class="px-8 py-6 text-gray-500 font-mono" x-text="d.type"></td>
                                        <td class="px-8 py-6 text-gray-600" x-text="d.id"></td>
                                        <td class="px-8 py-6">
                                            <span :class="'status-pill status-'+d.status" x-text="d.status"></span>
                                        </td>
                                        <td class="px-8 py-6 font-mono text-gray-400" x-text="':' + d.port"></td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- NEW DEPLOY -->
            <div x-show="currentPage==='new-deploy'">
                <div class="mb-12">
                    <h1 class="text-4xl font-heading font-extrabold uppercase tracking-tighter">Initial Manifest</h1>
                    <p class="text-gray-500 text-[10px] font-bold uppercase tracking-widest mt-2">Authorize New Infrastructure</p>
                </div>
                <div class="grid md:grid-cols-2 gap-8">
                    <div @click="navigate('ai-coder')" class="glass p-10 rounded-[40px] hover:border-white/40 cursor-pointer transition-all group">
                        <div class="w-12 h-12 border border-white/10 flex items-center justify-center mb-8 group-hover:bg-white group-hover:text-black transition-all">
                            <i class="fas fa-brain"></i>
                        </div>
                        <h3 class="text-xl font-heading font-bold uppercase mb-4">Neural Genesis</h3>
                        <p class="text-gray-500 text-sm leading-relaxed mb-10">Describe your vision. Our AI manifest engine will generate and deploy the entire architecture.</p>
                        <div class="text-[10px] font-bold uppercase text-white tracking-widest">Launch Generator →</div>
                    </div>
                    <div @click="navigate('github-deploy')" class="glass p-10 rounded-[40px] hover:border-white/40 cursor-pointer transition-all group">
                        <div class="w-12 h-12 border border-white/10 flex items-center justify-center mb-8 group-hover:bg-white group-hover:text-black transition-all">
                            <i class="fab fa-github"></i>
                        </div>
                        <h3 class="text-xl font-heading font-bold uppercase mb-4">VCS Synchronization</h3>
                        <p class="text-gray-500 text-sm leading-relaxed mb-10">Connect your GitHub repository for continuous deployment and direct version control.</p>
                        <div class="text-[10px] font-bold uppercase text-white tracking-widest">Connect Repository →</div>
                    </div>
                    <div @click="navigate('raw-deploy')" class="glass p-10 rounded-[40px] hover:border-white/40 cursor-pointer transition-all group">
                        <div class="w-12 h-12 border border-white/10 flex items-center justify-center mb-8 group-hover:bg-white group-hover:text-black transition-all">
                            <i class="fas fa-code"></i>
                        </div>
                        <h3 class="text-xl font-heading font-bold uppercase mb-4">Raw Transcription</h3>
                        <p class="text-gray-500 text-sm leading-relaxed mb-10">Paste raw code artifacts directly into the terminal for instantaneous broadcast.</p>
                        <div class="text-[10px] font-bold uppercase text-white tracking-widest">Open Editor →</div>
                    </div>
                    <div class="glass p-10 rounded-[40px] border-dashed border-white/10 flex flex-col items-center justify-center text-center">
                        <i class="fas fa-cloud-upload-alt text-2xl text-gray-700 mb-6"></i>
                        <h3 class="text-sm font-bold uppercase mb-2">Dossier Ingestion</h3>
                        <p class="text-[10px] text-gray-600 font-bold uppercase mb-8">ZIP OR SINGLE SOURCE FILE</p>
                        <input type="file" id="fileInput" class="hidden" @change="uploadFile($event)">
                        <button onclick="document.getElementById('fileInput').click()" class="btn-outline px-8 py-3 rounded-xl text-[10px] uppercase font-bold tracking-widest">Select Archive</button>
                    </div>
                </div>
            </div>

            <!-- GITHUB DEPLOY -->
            <div x-show="currentPage==='github-deploy'">
                <div class="flex items-center gap-6 mb-12">
                    <button @click="navigate('new-deploy')" class="w-10 h-10 border border-white/10 flex items-center justify-center hover:bg-white hover:text-black transition-all"><i class="fas fa-arrow-left text-xs"></i></button>
                    <h1 class="text-4xl font-heading font-extrabold uppercase tracking-tighter">VCS Sync</h1>
                </div>
                <div class="glass p-12 rounded-[40px] max-w-2xl">
                    <form @submit.prevent="deployGithub()" class="space-y-8">
                        <div>
                            <label class="text-[10px] font-bold uppercase text-gray-500 tracking-widest mb-3 block">Repository URL</label>
                            <input type="url" x-model="githubForm.url" required placeholder="https://github.com/identity/manifest"
                                   class="w-full bg-white/5 border border-white/10 px-6 py-4 rounded-xl text-sm focus:border-white outline-none">
                        </div>
                        <div class="grid grid-cols-2 gap-6">
                            <div>
                                <label class="text-[10px] font-bold uppercase text-gray-500 tracking-widest mb-3 block">Target Branch</label>
                                <input type="text" x-model="githubForm.branch" placeholder="main"
                                       class="w-full bg-white/5 border border-white/10 px-6 py-4 rounded-xl text-sm outline-none">
                            </div>
                            <div>
                                <label class="text-[10px] font-bold uppercase text-gray-500 tracking-widest mb-3 block">Build Script</label>
                                <input type="text" x-model="githubForm.buildCmd" placeholder="npm run build"
                                       class="w-full bg-white/5 border border-white/10 px-6 py-4 rounded-xl text-sm outline-none">
                            </div>
                        </div>
                        <button type="submit" class="btn-white w-full py-5 rounded-xl text-[11px] font-bold uppercase tracking-widest" :disabled="deploying">
                            <span x-show="!deploying">Authorize Synchronization (2.0 CR)</span>
                            <span x-show="deploying"><i class="fas fa-spinner fa-spin mr-2"></i>Provisioning...</span>
                        </button>
                    </form>
                </div>
            </div>

            <!-- AI CODER -->
            <div x-show="currentPage==='ai-coder'">
                <div class="flex items-center gap-6 mb-12">
                    <button @click="navigate('new-deploy')" class="w-10 h-10 border border-white/10 flex items-center justify-center hover:bg-white hover:text-black transition-all"><i class="fas fa-arrow-left text-xs"></i></button>
                    <h1 class="text-4xl font-heading font-extrabold uppercase tracking-tighter">Neural Genesis</h1>
                </div>
                <div class="glass p-12 rounded-[40px] mb-8">
                    <p class="text-[10px] font-bold text-gray-500 uppercase tracking-[0.3em] mb-6">Describe Architecture Parameters</p>
                    <textarea x-model="aiPrompt" rows="6" class="w-full bg-white/5 border border-white/10 p-8 rounded-3xl text-sm focus:border-white outline-none mb-8 resize-none" placeholder="e.g. Build a high-performance Flask API for portfolio management with JWT auth..."></textarea>
                    <button @click="generateAICode()" class="btn-white w-full py-5 rounded-xl text-[11px] font-bold uppercase tracking-widest" :disabled="aiGenerating">
                        <span x-show="!aiGenerating">Synthesize Manifest</span>
                        <span x-show="aiGenerating"><i class="fas fa-spinner fa-spin mr-2"></i>Neural Analysis in Progress...</span>
                    </button>
                </div>
                <div x-show="generatedCode" class="animate-fade-in">
                    <div class="flex justify-between items-center mb-4 px-2">
                        <span class="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Synthesized Output</span>
                        <div class="flex gap-4">
                            <input x-model="aiFilename" class="bg-transparent border-b border-white/20 text-xs font-mono py-1 focus:border-white outline-none text-right">
                            <button @click="deployRawCode(generatedCode, aiFilename)" class="text-[10px] font-bold text-white uppercase hover:underline">Authorize Deployment (1.0 CR) →</button>
                        </div>
                    </div>
                    <pre class="glass p-8 rounded-3xl font-mono text-xs overflow-x-auto text-gray-400 custom-scrollbar max-h-[500px]" x-text="generatedCode"></pre>
                </div>
            </div>

            <!-- WALLET -->
            <div x-show="currentPage==='credits'">
                <div class="mb-12">
                    <h1 class="text-4xl font-heading font-extrabold uppercase tracking-tighter">Financial Treasury</h1>
                    <p class="text-gray-500 text-[10px] font-bold uppercase tracking-widest mt-2">Capital Acquisition & Management</p>
                </div>
                <div class="grid md:grid-cols-3 gap-8 mb-12">
                    <div class="glass p-10 rounded-[40px] flex flex-col">
                        <h4 class="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-8">Base Package</h4>
                        <div class="text-4xl font-heading font-bold mb-2">10 Credits</div>
                        <div class="text-xl font-bold mb-10 text-gray-400">₹50</div>
                        <button @click="selectPackage('10_credits')" class="btn-white w-full py-4 rounded-xl text-[10px] uppercase tracking-widest mt-auto">Acquire</button>
                    </div>
                    <div class="glass p-10 rounded-[40px] flex flex-col border-white/30">
                        <h4 class="text-[10px] font-bold text-white uppercase tracking-widest mb-8">Professional</h4>
                        <div class="text-4xl font-heading font-bold mb-2">99 Credits</div>
                        <div class="text-xl font-bold mb-10 text-white">₹399</div>
                        <button @click="selectPackage('99_credits')" class="btn-white w-full py-4 rounded-xl text-[10px] uppercase tracking-widest mt-auto">Acquire</button>
                    </div>
                    <div class="glass p-10 rounded-[40px] flex flex-col border-dashed border-white/20">
                        <h4 class="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-8">Bespoke</h4>
                        <input type="number" x-model="customAmount" placeholder="Min ₹10" class="w-full bg-white/5 border border-white/10 px-6 py-4 rounded-xl text-sm outline-none mb-8">
                        <button @click="selectCustomPackage()" class="btn-outline w-full py-4 rounded-xl text-[10px] uppercase tracking-widest mt-auto">Invoice</button>
                    </div>
                </div>

                <div class="grid md:grid-cols-2 gap-8">
                    <!-- Referral -->
                    <div class="glass p-10 rounded-[40px]">
                        <h3 class="text-sm font-bold uppercase tracking-widest mb-8">Affiliate Protocol</h3>
                        <div class="bg-white/5 p-6 rounded-2xl mb-8">
                            <p class="text-[9px] font-bold text-gray-600 uppercase tracking-widest mb-2">Your Referral Identity</p>
                            <div class="flex items-center justify-between">
                                <span class="font-mono text-lg font-bold" x-text="refStats.referral_code"></span>
                                <button @click="copy(refStats.referral_code)" class="text-[10px] font-bold uppercase hover:text-white text-gray-500">Copy Code</button>
                            </div>
                        </div>
                        <div class="grid grid-cols-2 gap-4 text-center">
                            <div class="border border-white/5 p-4 rounded-xl">
                                <p class="text-[9px] font-bold text-gray-600 uppercase mb-1">Referrals</p>
                                <span class="text-xl font-bold" x-text="refStats.count"></span>
                            </div>
                            <div class="border border-white/5 p-4 rounded-xl">
                                <p class="text-[9px] font-bold text-gray-600 uppercase mb-1">Commission</p>
                                <span class="text-xl font-bold">30%</span>
                            </div>
                        </div>
                    </div>
                    <!-- Withdrawal -->
                    <div class="glass p-10 rounded-[40px]">
                        <h3 class="text-sm font-bold uppercase tracking-widest mb-8">Withdrawal Manifest</h3>
                        <p class="text-[10px] text-gray-500 mb-8 uppercase tracking-wide leading-relaxed">Liquidate your affiliate earnings. Minimum threshold: ₹500.</p>
                        <div class="flex gap-4">
                            <input type="number" x-model="withdrawAmount" placeholder="Amount" class="flex-1 bg-white/5 border border-white/10 px-6 py-4 rounded-xl text-sm outline-none">
                            <button @click="requestWithdrawal()" class="btn-white px-8 rounded-xl text-[10px] font-bold uppercase">Execute</button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- DEPLOYMENTS -->
            <div x-show="currentPage==='deployments'">
                <div class="flex justify-between items-end mb-12">
                    <div>
                        <h1 class="text-4xl font-heading font-extrabold uppercase tracking-tighter">Active Presence</h1>
                        <p class="text-gray-500 text-[10px] font-bold uppercase tracking-widest mt-2">Infrastructure Fleet Management</p>
                    </div>
                    <button @click="loadDeployments()" class="btn-outline px-6 py-3 rounded-xl text-[10px] uppercase font-bold"><i class="fas fa-sync mr-2"></i>Sync</button>
                </div>
                <div class="grid gap-6">
                    <template x-for="d in deployments" :key="d.id">
                        <div class="glass p-8 rounded-[32px] hover:border-white/30 transition-all flex flex-col md:flex-row justify-between items-center gap-8">
                            <div class="flex items-center gap-6">
                                <div class="w-12 h-12 border border-white/10 flex items-center justify-center font-bold text-sm" x-text="d.name[0].toUpperCase()"></div>
                                <div>
                                    <h3 class="text-lg font-bold uppercase tracking-tighter" x-text="d.name"></h3>
                                    <div class="flex gap-4 text-[9px] font-bold text-gray-500 uppercase tracking-widest mt-1">
                                        <span x-text="d.id"></span>
                                        <span x-text="d.type"></span>
                                        <span x-text="'PORT ' + d.port"></span>
                                    </div>
                                </div>
                            </div>
                            <div class="flex items-center gap-4">
                                <span :class="'status-pill status-'+d.status" x-text="d.status"></span>
                                <div class="h-8 w-px bg-white/10 mx-2"></div>
                                <button @click="viewDeployment(d.id)" class="text-[10px] font-bold uppercase tracking-widest hover:text-white text-gray-500">Manage</button>
                                <button @click="viewLogs(d.id)" class="text-[10px] font-bold uppercase tracking-widest hover:text-white text-gray-500">Terminal</button>
                            </div>
                        </div>
                    </template>
                </div>
            </div>

        </div>
    </main>

    <!-- Details Modal -->
    <div x-show="modal==='details'" x-cloak class="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/90 backdrop-blur-sm">
        <div class="glass w-full max-w-5xl max-h-[85vh] rounded-[40px] flex flex-col overflow-hidden animate-zoom-in">
            <div class="p-8 border-b border-white/5 flex justify-between items-center">
                <div class="flex items-center gap-4">
                    <h2 class="text-xl font-heading font-extrabold uppercase tracking-tighter" x-text="selectedDeploy?.name"></h2>
                    <span :class="'status-pill status-'+selectedDeploy?.status" x-text="selectedDeploy?.status"></span>
                </div>
                <button @click="modal=null" class="w-10 h-10 flex items-center justify-center hover:bg-white/5 rounded-full"><i class="fas fa-times"></i></button>
            </div>
            <div class="flex-1 flex overflow-hidden">
                <!-- Sidebar -->
                <div class="w-48 border-r border-white/5 p-6 space-y-2">
                    <template x-for="tab in ['Artifacts','Terminal','Config','Backups']" :key="tab">
                        <button @click="detailsTab=tab.toLowerCase()"
                                :class="detailsTab===tab.toLowerCase() ? 'bg-white text-black' : 'text-gray-500 hover:text-white'"
                                class="w-full text-left px-4 py-2.5 rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all" x-text="tab"></button>
                    </template>
                    <div class="pt-6 mt-6 border-t border-white/5 space-y-4">
                        <button @click="restartDeploy(selectedDeploy.id)" class="w-full text-left text-xs font-bold text-gray-400 hover:text-white"><i class="fas fa-redo mr-2"></i> Recycle</button>
                        <button @click="stopDeploy(selectedDeploy.id)" class="w-full text-left text-xs font-bold text-gray-400 hover:text-white"><i class="fas fa-stop mr-2"></i> Terminate</button>
                        <button @click="deleteDeploy(selectedDeploy.id)" class="w-full text-left text-xs font-bold text-red-900 hover:text-red-500"><i class="fas fa-trash mr-2"></i> Purge</button>
                    </div>
                </div>
                <!-- Content -->
                <div class="flex-1 p-10 overflow-y-auto custom-scrollbar">

                    <div x-show="detailsTab==='artifacts'">
                        <div class="flex justify-between items-center mb-8">
                            <h3 class="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Source Artifacts</h3>
                            <button @click="loadFiles()" class="text-[9px] font-bold uppercase">Sync Filesystem</button>
                        </div>
                        <div class="grid gap-2">
                            <template x-for="f in deployFiles" :key="f.path">
                                <div class="flex items-center justify-between p-4 bg-white/[0.02] rounded-xl border border-white/5 hover:border-white/10">
                                    <div class="flex items-center gap-4">
                                        <i class="far fa-file-code text-gray-600"></i>
                                        <span class="font-mono text-xs" x-text="f.path"></span>
                                    </div>
                                    <div class="flex gap-6 items-center">
                                        <span class="text-[9px] font-bold text-gray-600 uppercase" x-text="formatBytes(f.size)"></span>
                                        <button @click="editFile(f.path)" class="text-[10px] font-bold uppercase hover:underline">Edit</button>
                                    </div>
                                </div>
                            </template>
                        </div>
                    </div>

                    <div x-show="detailsTab==='terminal'" class="h-full flex flex-col">
                        <div class="flex-1 bg-black rounded-3xl p-6 font-mono text-[11px] text-gray-400 overflow-y-auto custom-scrollbar leading-relaxed whitespace-pre-wrap" x-text="consoleLogs"></div>
                        <div class="mt-4 flex justify-between items-center text-[9px] font-bold text-gray-600 uppercase">
                            <span>Live SSE Link Status: <span class="text-white" x-text="sseConnected ? 'Connected' : 'Offline'"></span></span>
                            <button @click="consoleLogs=''" class="hover:text-white">Clear Terminal</button>
                        </div>
                    </div>

                    <div x-show="detailsTab==='config'">
                         <!-- Env vars etc -->
                         <h3 class="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-6">Environmental Variables</h3>
                         <div class="space-y-4 mb-8">
                             <template x-for="[k, v] in Object.entries(selectedDeploy?.env_vars || {})" :key="k">
                                 <div class="flex items-center gap-4">
                                     <input readonly :value="k" class="bg-white/5 border border-white/5 px-4 py-2 rounded-lg text-xs font-mono w-1/3">
                                     <input readonly :value="v" class="bg-white/5 border border-white/5 px-4 py-2 rounded-lg text-xs font-mono flex-1">
                                     <button @click="deleteEnvVar(k)" class="text-red-900 hover:text-red-500 p-2"><i class="fas fa-times"></i></button>
                                 </div>
                             </template>
                         </div>
                         <div class="flex gap-4 p-4 border border-white/5 rounded-2xl bg-white/[0.01]">
                             <input x-model="newEnv.key" placeholder="KEY" class="bg-transparent border-b border-white/10 outline-none text-xs font-mono px-2 py-1 w-1/3">
                             <input x-model="newEnv.value" placeholder="VALUE" class="bg-transparent border-b border-white/10 outline-none text-xs font-mono px-2 py-1 flex-1">
                             <button @click="addEnvVar()" class="text-xs font-bold uppercase hover:text-white">Add</button>
                         </div>
                    </div>

                    <div x-show="detailsTab==='backups'">
                        <div class="text-center py-20">
                            <i class="fas fa-archive text-4xl text-gray-800 mb-6"></i>
                            <h3 class="text-sm font-bold uppercase mb-2">Artifact Archival</h3>
                            <p class="text-xs text-gray-600 max-w-xs mx-auto mb-10">Snapshots allow for immediate restoration to previous architectural states.</p>
                            <button @click="createBackup()" class="btn-outline px-10 py-4 rounded-xl text-[10px] font-bold uppercase tracking-widest">Generate Snapshot (0.5 CR)</button>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    </div>

    <!-- Editor Modal -->
    <div x-show="modal==='editor'" x-cloak class="fixed inset-0 z-[60] flex items-center justify-center p-6 bg-black/95">
        <div class="w-full max-w-4xl h-[80vh] flex flex-col glass rounded-[40px] overflow-hidden">
            <div class="p-6 border-b border-white/5 flex justify-between items-center">
                <div class="flex items-center gap-4">
                    <span class="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Editing Artifact</span>
                    <span class="font-mono text-xs text-white" x-text="editingPath"></span>
                </div>
                <button @click="modal='details'" class="text-xs font-bold uppercase hover:underline">Close Editor</button>
            </div>
            <textarea x-model="fileContent" class="flex-1 bg-black p-10 font-mono text-sm text-gray-300 outline-none resize-none custom-scrollbar leading-relaxed"></textarea>
            <div class="p-6 border-t border-white/5 flex justify-end gap-6">
                <button @click="saveFile()" class="btn-white px-10 py-3 rounded-xl text-[10px] font-bold uppercase tracking-widest">Authorize Changes</button>
            </div>
        </div>
    </div>

    <!-- Payment Modal -->
    <div x-show="modal==='payment'" x-cloak class="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/95">
        <div class="glass max-w-md w-full p-10 rounded-[40px] text-center">
            <h2 class="text-xl font-heading font-extrabold uppercase tracking-tighter mb-8">Capital Acquisition</h2>
            <div class="bg-white rounded-3xl p-6 mb-8 inline-block mx-auto">
                <img src="/qr.jpg" alt="QR" class="w-48 h-48 object-contain">
            </div>
            <div class="space-y-6 text-left mb-8">
                <div>
                    <label class="text-[9px] font-bold text-gray-500 uppercase tracking-widest block mb-2 px-1">Proof of Investment (Screenshot)</label>
                    <input type="file" @change="uploadScreenshot($event)" class="text-xs text-gray-500 file:bg-white/10 file:border-0 file:text-white file:px-4 file:py-2 file:rounded-lg file:mr-4 file:text-[9px] file:font-bold file:uppercase cursor-pointer">
                </div>
                <div>
                    <label class="text-[9px] font-bold text-gray-500 uppercase tracking-widest block mb-2 px-1">Transaction ID / UTR</label>
                    <input type="text" x-model="paymentData.transactionId" class="w-full bg-white/5 border border-white/10 p-4 rounded-xl text-sm outline-none focus:border-white">
                </div>
            </div>
            <button @click="submitPayment()" class="btn-white w-full py-4 rounded-xl text-[11px] font-bold uppercase tracking-widest">Verify Transaction</button>
            <button @click="modal=null" class="mt-6 text-[10px] font-bold text-gray-600 uppercase hover:text-white">Cancel</button>
        </div>
    </div>

    <script>
    function dashApp() {
        return {
            currentPage: 'overview',
            modal: null,
            detailsTab: 'artifacts',
            credits: 0,
            wallet: {},
            trial: {},
            trialCountdown: '',
            deployments: [],
            stats: { total: 0, running: 0 },
            selectedDeploy: null,
            deployFiles: [],
            editingPath: '',
            fileContent: '',
            consoleLogs: '',
            deploying: false,
            githubForm: { url: '', branch: 'main', buildCmd: '' },
            aiPrompt: '',
            aiGenerating: false,
            generatedCode: '',
            aiFilename: 'main.py',
            refStats: {},
            withdrawAmount: 0,
            paymentData: { transactionId: '' },
            newEnv: { key: '', value: '' },
            customAmount: 0,
            sseConnected: false,
            navItems: [
                { id: 'overview', icon: 'fas fa-columns', label: 'Command' },
                { id: 'deployments', icon: 'fas fa-rocket', label: 'Fleet' },
                { id: 'new-deploy', icon: 'fas fa-plus', label: 'Manifest' },
                { id: 'credits', icon: 'fas fa-wallet', label: 'Treasury' },
            ],

            init() {
                this.refreshAll();
                setInterval(() => this.refreshAll(), 30000);
                this.connectSSE();
                setInterval(() => this.updateTrialTimer(), 1000);
            },
            async refreshAll() {
                await Promise.all([this.loadCredits(), this.loadDeployments(), this.loadWallet(), this.loadReferralStats()]);
            },
            async loadCredits() {
                const r = await fetch('/api/credits');
                const d = await r.json();
                if (d.success) { this.credits = d.credits; this.trial = d.trial; }
            },
            async loadDeployments() {
                const r = await fetch('/api/deployments');
                const d = await r.json();
                if (d.success) {
                    this.deployments = d.deployments;
                    this.stats.total = d.deployments.length;
                    this.stats.running = d.deployments.filter(x => x.status === 'running').length;
                }
            },
            async loadWallet() {
                const r = await fetch('/api/finance/wallet');
                const d = await r.json();
                if (d.success) this.wallet = d.wallet;
            },
            async loadReferralStats() {
                const r = await fetch('/api/referral/stats');
                const d = await r.json();
                if (d.success) this.refStats = d.stats;
            },
            updateTrialTimer() {
                if (!this.trial || this.trial.status !== 'active') { this.trialCountdown = ''; return; }
                const end = new Date(this.trial.end_time).getTime();
                const now = new Date().getTime();
                const dist = end - now;
                if (dist < 0) { this.trialCountdown = 'EXPIRED'; return; }
                const h = Math.floor(dist / 3600000), m = Math.floor((dist % 3600000) / 60000), s = Math.floor((dist % 60000) / 1000);
                this.trialCountdown = `${h}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
            },
            navigate(page) { this.currentPage = page; },
            logout() { if(confirm('Terminate current access?')) window.location.href='/logout'; },
            async viewDeployment(id) {
                this.selectedDeploy = this.deployments.find(x => x.id === id);
                this.modal = 'details'; this.detailsTab = 'artifacts'; this.loadFiles(); this.loadLogs();
            },
            async loadFiles() {
                const r = await fetch(`/api/deployment/${this.selectedDeploy.id}/files`);
                const d = await r.json();
                if (d.success) this.deployFiles = d.files;
            },
            async loadLogs() {
                const r = await fetch(`/api/deployment/${this.selectedDeploy.id}/logs`);
                const d = await r.json();
                if (d.success) this.consoleLogs = d.logs;
            },
            async editFile(path) {
                this.editingPath = path;
                const r = await fetch(`/api/deployment/${this.selectedDeploy.id}/file?path=${path}`);
                const d = await r.json();
                if (d.success) { this.fileContent = d.content; this.modal = 'editor'; }
            },
            async saveFile() {
                const r = await fetch(`/api/deployment/${this.selectedDeploy.id}/file?path=${this.editingPath}`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content: this.fileContent })
                });
                if ((await r.json()).success) { alert('Artifact Authorized'); this.modal = 'details'; }
            },
            async generateAICode() {
                this.aiGenerating = true;
                const r = await fetch('/api/ai/generate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ prompt: this.aiPrompt }) });
                const d = await r.json();
                if (d.success) this.generatedCode = d.code;
                this.aiGenerating = false;
            },
            async deployRawCode(code, filename) {
                this.deploying = true;
                const r = await fetch('/api/deploy/raw', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code, filename }) });
                const d = await r.json();
                if (d.success) { alert('Manifest Active'); this.navigate('deployments'); this.modal = null; } else alert(d.error);
                this.deploying = false;
            },
            async deployGithub() {
                this.deploying = true;
                const r = await fetch('/api/deploy/github', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(this.githubForm) });
                const d = await r.json();
                if (d.success) { alert('Sync Active'); this.navigate('deployments'); } else alert(d.error);
                this.deploying = false;
            },
            async stopDeploy(id) { if(confirm('Terminate deployment?')) await fetch(`/api/deployment/${id}/stop`, {method:'POST'}); this.loadDeployments(); },
            async restartDeploy(id) { await fetch(`/api/deployment/${id}/restart`, {method:'POST'}); alert('Recycling Environment...'); this.loadDeployments(); },
            async deleteDeploy(id) { if(confirm('Purge deployment from registry?')) { await fetch(`/api/deployment/${id}`, {method:'DELETE'}); this.modal=null; this.loadDeployments(); } },
            async createBackup() { await fetch(`/api/deployment/${this.selectedDeploy.id}/backup`, {method:'POST'}); alert('Snapshot Generated'); },
            async requestWithdrawal() {
                const r = await fetch('/api/finance/withdraw', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({amount: this.withdrawAmount, method: 'Tether/UPI'}) });
                const d = await r.json();
                if (d.success) alert('Withdrawal Initiated'); else alert(d.error);
            },
            async selectPackage(pkg) {
                const r = await fetch('/api/payment/create', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({package_type: pkg}) });
                const d = await r.json();
                if (d.success) { this.paymentData.id = d.payment.id; this.modal = 'payment'; }
            },
            async selectCustomPackage() {
                const r = await fetch('/api/payment/create', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({package_type: 'custom', custom_amount: this.customAmount}) });
                const d = await r.json();
                if (d.success) { this.paymentData.id = d.payment.id; this.modal = 'payment'; }
            },
            uploadScreenshot(e) {
                const reader = new FileReader();
                reader.onload = (ev) => { this.paymentData.screenshot = ev.target.result; };
                reader.readAsDataURL(e.target.files[0]);
            },
            async submitPayment() {
                const r = await fetch('/api/payment/submit', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({payment_id: this.paymentData.id, screenshot: this.paymentData.screenshot, transaction_id: this.paymentData.transactionId}) });
                if ((await r.json()).success) { alert('Transaction Pending Verification'); this.modal = null; }
            },
            connectSSE() {
                const es = new EventSource('/api/events');
                es.onopen = () => this.sseConnected = true;
                es.onmessage = (e) => {
                    const ev = JSON.parse(e.data);
                    if (ev.type === 'logs' && this.selectedDeploy?.id === ev.data.id) {
                        this.consoleLogs += ev.data.line;
                    }
                };
                es.onerror = () => { this.sseConnected = false; };
            },
            formatBytes(b) { if(b===0) return '0 B'; const k=1024, s=['B','KB','MB','GB'], i=Math.floor(Math.log(b)/Math.log(k)); return parseFloat((b/Math.pow(k,i)).toFixed(1))+' '+s[i]; },
            copy(t) { navigator.clipboard.writeText(t); alert('Copied'); }
        }
    }
    </script>
</body>
</html>"""

# ==================== ADMIN PANEL HTML ====================
ADMIN_PANEL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost — Concierge Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@700;800&family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #000000; --card: #080808; --border: #1a1a1a; }
        body { font-family: 'Inter', sans-serif; background: var(--bg); color: #fff; }
        .font-heading { font-family: 'Plus Jakarta Sans', sans-serif; }
        .glass { background: var(--card); border: 1px solid var(--border); }
        .btn-white { background: #fff; color: #000; font-weight: 700; }
        .btn-outline { border: 1px solid var(--border); background: transparent; color: #fff; }
        .btn-outline:hover { background: #111; }
        table th { text-transform: uppercase; letter-spacing: 1.5px; font-size: 9px; color: #666; font-weight: 800; padding: 16px 24px; }
        table td { padding: 16px 24px; font-size: 11px; border-bottom: 1px solid #111; }
    </style>
</head>
<body x-data="{ tab: 'users' }">
    <header class="border-b border-white/5 p-8 flex justify-between items-center sticky top-0 bg-black/80 backdrop-blur-md z-50">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 border border-white flex items-center justify-center font-bold">E</div>
            <h1 class="text-xl font-heading font-extrabold uppercase tracking-tighter">Concierge Admin</h1>
        </div>
        <div class="flex gap-4">
            <template x-for="t in ['users','payments','withdrawals','tickets']" :key="t">
                <button @click="tab=t" :class="tab===t ? 'text-white border-b border-white' : 'text-gray-500'" class="pb-1 text-[10px] font-bold uppercase tracking-widest" x-text="t"></button>
            </template>
        </div>
    </header>

    <main class="max-w-7xl mx-auto p-8">
        <!-- Dashboard Stats -->
        <div class="grid grid-cols-4 gap-6 mb-12">
            <div class="glass p-8 rounded-3xl">
                <p class="text-[9px] font-bold text-gray-500 uppercase tracking-widest mb-2">Total Users</p>
                <div class="text-3xl font-heading font-extrabold">{{ stats.total_users }}</div>
            </div>
            <div class="glass p-8 rounded-3xl">
                <p class="text-[9px] font-bold text-gray-500 uppercase tracking-widest mb-2">Active Procs</p>
                <div class="text-3xl font-heading font-extrabold">{{ stats.active_processes }}</div>
            </div>
            <div class="glass p-8 rounded-3xl">
                <p class="text-[9px] font-bold text-gray-500 uppercase tracking-widest mb-2">Pending Invoices</p>
                <div class="text-3xl font-heading font-extrabold text-white">{{ stats.pending_payments }}</div>
            </div>
            <div class="glass p-8 rounded-3xl">
                <p class="text-[9px] font-bold text-gray-500 uppercase tracking-widest mb-2">Pending Cashout</p>
                <div class="text-3xl font-heading font-extrabold">{{ stats.pending_withdrawals }}</div>
            </div>
        </div>

        <!-- Users -->
        <div x-show="tab==='users'" class="glass rounded-3xl overflow-hidden">
            <table class="w-full text-left">
                <thead>
                    <tr class="bg-white/[0.02]">
                        <th>Identity</th>
                        <th>Credits</th>
                        <th>Affiliate</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for u in users %}
                    <tr>
                        <td class="font-bold">{{ u.email }}</td>
                        <td class="font-mono">{{ u.credits }}</td>
                        <td class="text-gray-500">{{ u.referral_code }}</td>
                        <td>
                            {% if u.is_banned %}<span class="text-red-500">BANNED</span>{% else %}<span class="text-green-500">ACTIVE</span>{% endif %}
                        </td>
                        <td>
                            <div class="flex gap-4">
                                <button onclick="banUser('{{u.id}}', {{ 'false' if u.is_banned else 'true' }})" class="text-[9px] font-bold uppercase">{{ 'Restore' if u.is_banned else 'Revoke' }}</button>
                                <button onclick="addCredits('{{u.id}}')" class="text-[9px] font-bold uppercase">Grant</button>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Tickets -->
        <div x-show="tab==='tickets'" class="glass rounded-3xl overflow-hidden">
            <table class="w-full text-left">
                <thead>
                    <tr class="bg-white/[0.02]">
                        <th>Ticket</th>
                        <th>User</th>
                        <th>Subject</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for t in tickets %}
                    <tr>
                        <td class="font-bold">{{ t.id }}</td>
                        <td>{{ t.user_id }}</td>
                        <td>{{ t.subject }}</td>
                        <td>{{ t.status }}</td>
                        <td>
                            <button onclick="viewTicket('{{t.id}}')" class="text-xs font-bold">Open Chat</button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Payments -->
        <div x-show="tab==='payments'" class="glass rounded-3xl overflow-hidden">
            <table class="w-full text-left">
                <thead>
                    <tr class="bg-white/[0.02]">
                        <th>Client</th>
                        <th>Amount</th>
                        <th>TXN ID</th>
                        <th>State</th>
                        <th>Verify</th>
                    </tr>
                </thead>
                <tbody>
                    {% for p in payments %}
                    <tr>
                        <td class="font-bold">{{ p.user_email }}</td>
                        <td class="font-mono text-white">₹{{ p.price }}</td>
                        <td class="text-gray-500 font-mono text-[10px]">{{ p.transaction_id }}</td>
                        <td><span class="text-[10px] font-bold uppercase">{{ p.status }}</span></td>
                        <td>
                            {% if p.status == 'submitted' %}
                            <div class="flex gap-3">
                                <button onclick="approvePayment('{{p.id}}')" class="text-white font-bold uppercase text-[9px]">Approve</button>
                                <button onclick="rejectPayment('{{p.id}}')" class="text-red-900 font-bold uppercase text-[9px]">Deny</button>
                            </div>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Withdrawals -->
        <div x-show="tab==='withdrawals'" class="glass rounded-3xl overflow-hidden">
            <table class="w-full text-left">
                <thead>
                    <tr class="bg-white/[0.02]">
                        <th>UID</th>
                        <th>Value</th>
                        <th>Method</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for w in withdrawals %}
                    <tr>
                        <td class="text-[10px]">{{ w.user_id }}</td>
                        <td class="font-bold">₹{{ w.amount }}</td>
                        <td>{{ w.method }}</td>
                        <td>{{ w.status }}</td>
                        <td>
                            {% if w.status == 'pending' %}
                            <button onclick="withdrawAction('{{w.id}}', 'approve')" class="text-xs font-bold">Approve</button>
                            {% elif w.status == 'approved' %}
                            <button onclick="withdrawAction('{{w.id}}', 'paid')" class="text-xs font-bold text-green-500">Mark Paid</button>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </main>

    <script>
        async function banUser(id, ban) { await fetch('/api/admin/ban-user', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({user_id:id, ban})}); location.reload(); }
        async function addCredits(id) { const a = prompt('Amount'); await fetch('/api/admin/add-credits', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({user_id:id, amount:parseFloat(a)})}); location.reload(); }
        async function approvePayment(id) { await fetch('/api/admin/approve-payment', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({payment_id:id})}); location.reload(); }
        async function withdrawAction(id, action) { await fetch(`/api/admin/withdrawal/${id}/${action}`, {method:'POST'}); location.reload(); }
    </script>
</body>
</html>"""
