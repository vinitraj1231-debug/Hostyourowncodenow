LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost v14 - {{ title }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        body { background: radial-gradient(ellipse at 20% 50%, #1e3a5f 0%, #0f172a 50%, #1a0533 100%); }
        .glass { background: rgba(15,23,42,0.7); backdrop-filter: blur(20px); border: 1px solid rgba(59,130,246,0.15); }
        .btn-glow { box-shadow: 0 0 30px rgba(59,130,246,0.4); }
        .fade-in { animation: fadeIn 0.6s ease-out; }
        @keyframes fadeIn { from { opacity:0; transform:translateY(-20px); } to { opacity:1; transform:translateY(0); } }
        .particle { position:fixed; border-radius:50%; pointer-events:none; animation: float linear infinite; }
        @keyframes float { 0%{transform:translateY(100vh) scale(0);opacity:0;} 10%{opacity:1;} 90%{opacity:1;} 100%{transform:translateY(-100px) scale(1);opacity:0;} }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4 overflow-hidden">
    <div id="particles"></div>
    <div class="max-w-md w-full fade-in relative z-10">
        <div class="glass rounded-2xl shadow-2xl p-8">
            <div class="text-center mb-8">
                <div class="relative inline-block">
                    <div class="w-20 h-20 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-2xl mx-auto mb-4 flex items-center justify-center btn-glow">
                        <i class="fas fa-rocket text-white text-3xl"></i>
                    </div>
                    <div class="absolute -top-1 -right-1 w-5 h-5 bg-green-500 rounded-full border-2 border-slate-900 animate-pulse"></div>
                </div>
                <h1 class="text-3xl font-black text-white mb-1">EliteHost <span class="text-blue-400">v14</span></h1>
                <p class="text-slate-400 text-sm">{{ subtitle }}</p>
            </div>

            {% if error %}
            <div class="bg-red-500/10 border border-red-500/40 rounded-xl p-3 mb-4 text-red-400 text-sm fade-in flex items-center gap-2">
                <i class="fas fa-exclamation-circle"></i>{{ error }}
            </div>
            {% endif %}
            {% if success %}
            <div class="bg-green-500/10 border border-green-500/40 rounded-xl p-3 mb-4 text-green-400 text-sm fade-in flex items-center gap-2">
                <i class="fas fa-check-circle"></i>{{ success }}
            </div>
            {% endif %}

            <form method="POST" action="{{ action }}" class="space-y-4" id="authForm">
                <div>
                    <label class="block text-sm font-semibold text-slate-300 mb-2">
                        <i class="fas fa-envelope mr-2 text-blue-400"></i>Email
                    </label>
                    <input type="email" name="email" required autocomplete="email"
                        class="w-full px-4 py-3 bg-slate-900/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                        placeholder="your@email.com">
                </div>
                <div>
                    <label class="block text-sm font-semibold text-slate-300 mb-2">
                        <i class="fas fa-lock mr-2 text-blue-400"></i>Password
                    </label>
                    <div class="relative">
                        <input type="password" name="password" id="passwordField" required
                            class="w-full px-4 py-3 bg-slate-900/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition pr-12"
                            placeholder="••••••••">
                        <button type="button" onclick="togglePwd()" class="absolute right-3 top-3.5 text-slate-400 hover:text-white transition">
                            <i class="fas fa-eye" id="eyeIcon"></i>
                        </button>
                    </div>
                </div>
                <button type="submit" id="submitBtn"
                    class="w-full bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold py-3 px-4 rounded-xl hover:opacity-90 transition transform hover:scale-[1.02] active:scale-[0.98] btn-glow mt-2">
                    <i class="fas fa-{{ icon }} mr-2"></i><span id="btnText">{{ button_text }}</span>
                </button>
            </form>

            <p class="text-center mt-6 text-sm text-slate-400">
                {{ toggle_text }} <a href="{{ toggle_link }}" class="text-blue-400 hover:text-blue-300 font-semibold hover:underline transition">{{ toggle_action }}</a>
            </p>
            <div class="mt-6 pt-4 border-t border-slate-800 flex items-center justify-center gap-2 text-xs text-slate-500">
                <i class="fas fa-shield-alt text-blue-500"></i>
                <span>Device-Locked Security · EliteHost v14</span>
            </div>
        </div>
    </div>
    <script>
        function togglePwd(){
            const f=document.getElementById('passwordField'),i=document.getElementById('eyeIcon');
            f.type=f.type==='password'?'text':'password';
            i.className='fas fa-'+(f.type==='password'?'eye':'eye-slash');
        }
        document.getElementById('authForm').addEventListener('submit',function(e){
            const btn=document.getElementById('submitBtn'),txt=document.getElementById('btnText');
            btn.disabled=true; btn.classList.add('opacity-75');
            txt.innerHTML='<i class="fas fa-spinner fa-spin mr-2"></i>Processing...';
        });
        // Particles
        (function(){
            const c=document.getElementById('particles');
            for(let i=0;i<15;i++){
                const p=document.createElement('div');
                const size=Math.random()*4+2;
                p.className='particle';
                p.style.cssText=`width:${size}px;height:${size}px;left:${Math.random()*100}%;background:rgba(59,130,246,${Math.random()*0.5+0.1});animation-duration:${Math.random()*15+10}s;animation-delay:${Math.random()*10}s;`;
                c.appendChild(p);
            }
        })();
    </script>
</body>
</html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost v14 - Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        [x-cloak]{display:none!important}
        body{background:#060d1a}
        .glass{background:rgba(15,23,42,0.8);backdrop-filter:blur(16px);border:1px solid rgba(59,130,246,0.1)}
        .sidebar{background:linear-gradient(180deg,#0d1b2e 0%,#0a1628 100%);border-right:1px solid rgba(59,130,246,0.1)}
        .active-nav{background:linear-gradient(135deg,rgba(59,130,246,0.2),rgba(34,211,238,0.1));border:1px solid rgba(59,130,246,0.3);color:#fff}
        .stat-card{background:linear-gradient(135deg,rgba(15,23,42,0.9),rgba(30,58,95,0.3));border:1px solid rgba(59,130,246,0.1)}
        .glow-blue{box-shadow:0 0 20px rgba(59,130,246,0.3)}
        .glow-green{box-shadow:0 0 20px rgba(34,197,94,0.3)}
        .btn-primary{background:linear-gradient(135deg,#2563eb,#0891b2);transition:all .2s}
        .btn-primary:hover{opacity:.9;transform:translateY(-1px)}
        .status-running{background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3)}
        .status-stopped{background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)}
        .status-pending{background:rgba(234,179,8,0.15);color:#facc15;border:1px solid rgba(234,179,8,0.3)}
        .status-failed{background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)}
        .toast{position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;max-width:350px;animation:slideIn .3s ease}
        @keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
        .notification-badge{position:absolute;top:-4px;right:-4px;width:16px;height:16px;background:#ef4444;border-radius:50%;font-size:10px;display:flex;align-items:center;justify-content:center}
        .progress-bar{height:6px;border-radius:3px;transition:width 1s ease}
        ::-webkit-scrollbar{width:4px;height:4px}
        ::-webkit-scrollbar-track{background:#0d1b2e}
        ::-webkit-scrollbar-thumb{background:#1e40af;border-radius:2px}
    </style>
</head>
<body class="text-white min-h-screen" x-data="dashApp()">

    <!-- Notification Toasts -->
    <div class="toast-container" id="toastContainer"></div>

    <!-- Sidebar -->
    <div class="sidebar fixed inset-y-0 left-0 w-64 z-50 flex flex-col transform transition-transform duration-300"
         :class="sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'">
        <div class="p-6 flex items-center gap-3 border-b border-blue-900/30">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center glow-blue">
                <i class="fas fa-rocket text-white"></i>
            </div>
            <div>
                <span class="text-lg font-black text-white">EliteHost</span>
                <span class="text-xs text-blue-400 block">v14.0</span>
            </div>
        </div>

        <nav class="flex-1 p-4 space-y-1 overflow-y-auto">
            <template x-for="item in navItems" :key="item.id">
                <button @click="navigate(item.id)"
                    :class="currentPage===item.id ? 'active-nav' : 'text-slate-400 hover:bg-blue-900/20 hover:text-white'"
                    class="w-full flex items-center gap-3 px-4 py-3 rounded-xl cursor-pointer transition text-left">
                    <i :class="item.icon" class="w-5 text-center"></i>
                    <span x-text="item.label"></span>
                    <span x-show="item.badge && item.badge > 0"
                        class="ml-auto bg-blue-600 text-white text-xs px-2 py-0.5 rounded-full"
                        x-text="item.badge"></span>
                </button>
            </template>
            {% if is_admin %}
            <a href="/admin"
                class="flex items-center gap-3 px-4 py-3 rounded-xl text-yellow-400 hover:bg-yellow-500/10 hover:text-yellow-300 transition">
                <i class="fas fa-crown w-5 text-center"></i>
                <span>Admin Panel</span>
                <span class="ml-auto text-xs bg-yellow-500/20 px-2 py-0.5 rounded-full">ADMIN</span>
            </a>
            {% endif %}
        </nav>

        <div class="p-4 border-t border-blue-900/30">
            <div class="bg-gradient-to-r from-blue-600/20 to-cyan-600/20 border border-blue-500/30 rounded-xl p-4 mb-3">
                <div class="flex items-center justify-between mb-1">
                    <span class="text-xs text-blue-300">Available Credits</span>
                    <i class="fas fa-gem text-blue-400 text-xs"></i>
                </div>
                <div class="text-2xl font-black text-white" x-text="credits === Infinity ? '∞' : parseFloat(credits).toFixed(1)"></div>
                <div class="text-xs text-slate-400 mt-1">Click + to buy more</div>
            </div>
            <div class="grid grid-cols-2 gap-2">
                <button @click="navigate('buy-credits')"
                    class="bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 px-3 py-2 rounded-lg text-xs transition">
                    <i class="fas fa-plus mr-1"></i>Buy Credits
                </button>
                <button @click="logout()"
                    class="bg-red-600/20 hover:bg-red-600/30 text-red-400 px-3 py-2 rounded-lg text-xs transition">
                    <i class="fas fa-sign-out-alt mr-1"></i>Logout
                </button>
            </div>
        </div>
    </div>

    <!-- Mobile Header -->
    <div class="md:hidden fixed top-0 left-0 right-0 z-40 bg-slate-900/90 backdrop-blur border-b border-slate-800 px-4 py-3 flex items-center justify-between">
        <button @click="sidebarOpen=!sidebarOpen" class="text-white p-1">
            <i class="fas fa-bars text-xl"></i>
        </button>
        <span class="font-black text-white">EliteHost <span class="text-blue-400">v14</span></span>
        <div class="text-sm font-semibold text-blue-400" x-text="credits === Infinity ? '∞ cr' : parseFloat(credits).toFixed(1)+' cr'"></div>
    </div>

    <!-- Overlay -->
    <div x-show="sidebarOpen" @click="sidebarOpen=false"
         class="md:hidden fixed inset-0 bg-black/50 z-40" x-cloak></div>

    <!-- Main Content -->
    <main class="md:ml-64 min-h-screen pt-16 md:pt-0">
        <div class="p-4 md:p-8">

            <!-- OVERVIEW PAGE -->
            <div x-show="currentPage==='overview'" x-transition:enter="transition ease-out duration-200" x-transition:enter-start="opacity-0 translate-y-4" x-transition:enter-end="opacity-100 translate-y-0">
                <div class="flex items-center justify-between mb-8">
                    <div>
                        <h1 class="text-3xl font-black mb-1">Dashboard</h1>
                        <p class="text-slate-400 text-sm">Welcome back! Here's your overview.</p>
                    </div>
                    <div class="text-xs text-slate-500 flex items-center gap-2">
                        <div class="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                        <span id="liveIndicator">Live updates active</span>
                    </div>
                </div>

                <!-- Stats -->
                <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                    <div class="stat-card rounded-xl p-5">
                        <div class="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center mb-3">
                            <i class="fas fa-rocket text-blue-400"></i>
                        </div>
                        <div class="text-2xl font-black" x-text="stats.total"></div>
                        <div class="text-xs text-slate-400 mt-1">Total Deployments</div>
                    </div>
                    <div class="stat-card rounded-xl p-5">
                        <div class="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center mb-3">
                            <i class="fas fa-circle-check text-green-400"></i>
                        </div>
                        <div class="text-2xl font-black text-green-400" x-text="stats.running"></div>
                        <div class="text-xs text-slate-400 mt-1">Running Now</div>
                    </div>
                    <div class="stat-card rounded-xl p-5">
                        <div class="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center mb-3">
                            <i class="fas fa-gem text-blue-400"></i>
                        </div>
                        <div class="text-2xl font-black text-blue-400" x-text="credits === Infinity ? '∞' : parseFloat(credits).toFixed(1)"></div>
                        <div class="text-xs text-slate-400 mt-1">Credits</div>
                    </div>
                    <div class="stat-card rounded-xl p-5">
                        <div class="w-10 h-10 bg-cyan-500/20 rounded-lg flex items-center justify-center mb-3">
                            <i class="fas fa-robot text-cyan-400"></i>
                        </div>
                        <div class="text-2xl font-black text-cyan-400">AI</div>
                        <div class="text-xs text-slate-400 mt-1">Auto Deploy</div>
                    </div>
                </div>

                <!-- Recent Deployments -->
                <div class="glass rounded-2xl p-6">
                    <div class="flex items-center justify-between mb-5">
                        <h2 class="text-lg font-bold">Recent Deployments</h2>
                        <button @click="navigate('deployments')" class="text-blue-400 text-sm hover:underline">View all →</button>
                    </div>
                    <div class="space-y-3" x-show="deployments.length > 0">
                        <template x-for="d in deployments.slice(0,5)" :key="d.id">
                            <div class="bg-slate-800/40 rounded-xl p-4 flex items-center justify-between hover:bg-slate-800/60 transition">
                                <div class="flex items-center gap-4">
                                    <div class="w-9 h-9 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                        <i class="fas fa-rocket text-blue-400 text-sm"></i>
                                    </div>
                                    <div>
                                        <div class="font-semibold text-sm" x-text="d.name"></div>
                                        <div class="text-xs text-slate-400"><span x-text="d.id"></span> · Port <span x-text="d.port"></span></div>
                                    </div>
                                </div>
                                <span class="px-2.5 py-1 rounded-lg text-xs font-semibold"
                                      :class="'status-'+d.status" x-text="d.status.toUpperCase()"></span>
                            </div>
                        </template>
                    </div>
                    <div x-show="deployments.length===0" class="text-center py-16 text-slate-400">
                        <i class="fas fa-satellite-dish text-5xl mb-4 opacity-20"></i>
                        <p class="font-semibold">No deployments yet</p>
                        <p class="text-sm mt-1">Deploy your first app to get started!</p>
                        <button @click="navigate('new-deploy')" class="btn-primary mt-4 px-6 py-2 rounded-xl text-sm font-semibold">
                            <i class="fas fa-plus mr-2"></i>Deploy Now
                        </button>
                    </div>
                </div>
            </div>

            <!-- DEPLOYMENTS PAGE -->
            <div x-show="currentPage==='deployments'" x-transition:enter="transition ease-out duration-200" x-transition:enter-start="opacity-0 translate-y-4" x-transition:enter-end="opacity-100 translate-y-0">
                <div class="flex items-center justify-between mb-8">
                    <h1 class="text-3xl font-black">All Deployments</h1>
                    <button @click="loadDeployments(true)" class="btn-primary px-4 py-2 rounded-xl text-sm font-semibold">
                        <i class="fas fa-sync-alt mr-2"></i>Refresh
                    </button>
                </div>
                <div class="space-y-4">
                    <template x-for="d in deployments" :key="d.id">
                        <div class="glass rounded-2xl p-6 hover:border-blue-500/30 transition">
                            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
                                <div>
                                    <h3 class="text-lg font-bold mb-1" x-text="d.name"></h3>
                                    <div class="flex flex-wrap gap-3 text-xs text-slate-400">
                                        <span><i class="fas fa-fingerprint mr-1"></i><span x-text="d.id"></span></span>
                                        <span><i class="fas fa-network-wired mr-1"></i>Port <span x-text="d.port"></span></span>
                                        <span><i class="fas fa-code-branch mr-1"></i><span x-text="d.type"></span></span>
                                        <span x-show="d.restart_count > 0" class="text-yellow-400">
                                            <i class="fas fa-redo mr-1"></i>Restarted <span x-text="d.restart_count"></span>x
                                        </span>
                                    </div>
                                </div>
                                <span class="px-4 py-1.5 rounded-xl text-sm font-bold w-fit"
                                      :class="'status-'+d.status" x-text="d.status.toUpperCase()"></span>
                            </div>
                            <div class="flex flex-wrap gap-2">
                                <button @click="viewDeployment(d.id)" class="btn-primary px-4 py-2 rounded-xl text-xs font-semibold">
                                    <i class="fas fa-eye mr-1"></i>Details
                                </button>
                                <button @click="viewLogs(d.id)" class="bg-slate-700/50 hover:bg-slate-700 px-4 py-2 rounded-xl text-xs transition">
                                    <i class="fas fa-terminal mr-1"></i>Logs
                                </button>
                                <button @click="restartDeploy(d.id)" class="bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-400 px-4 py-2 rounded-xl text-xs transition" x-show="d.status==='running' || d.status==='stopped'">
                                    <i class="fas fa-redo mr-1"></i>Restart
                                </button>
                                <button @click="stopDeploy(d.id)" class="bg-orange-600/20 hover:bg-orange-600/30 text-orange-400 px-4 py-2 rounded-xl text-xs transition" x-show="d.status==='running'">
                                    <i class="fas fa-stop mr-1"></i>Stop
                                </button>
                                <button @click="deleteDeploy(d.id)" class="bg-red-600/20 hover:bg-red-600/30 text-red-400 px-4 py-2 rounded-xl text-xs transition">
                                    <i class="fas fa-trash mr-1"></i>Delete
                                </button>
                            </div>
                        </div>
                    </template>
                    <div x-show="deployments.length===0" class="glass rounded-2xl p-16 text-center">
                        <i class="fas fa-rocket text-6xl text-slate-700 mb-4"></i>
                        <h3 class="text-xl font-bold mb-2">No Deployments</h3>
                        <p class="text-slate-400 mb-6">Get started by deploying your first app</p>
                        <button @click="navigate('new-deploy')" class="btn-primary px-6 py-3 rounded-xl font-semibold">
                            <i class="fas fa-plus mr-2"></i>Create Deployment
                        </button>
                    </div>
                </div>
            </div>

            <!-- NEW DEPLOY PAGE -->
            <div x-show="currentPage==='new-deploy'" x-transition:enter="transition ease-out duration-200" x-transition:enter-start="opacity-0 translate-y-4" x-transition:enter-end="opacity-100 translate-y-0">
                <h1 class="text-3xl font-black mb-8">New Deployment</h1>
                <div class="grid md:grid-cols-2 gap-6">
                    <!-- File Upload -->
                    <div class="glass rounded-2xl p-6">
                        <div class="flex items-center gap-3 mb-5">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
                                <i class="fas fa-cloud-upload-alt text-blue-400 text-xl"></i>
                            </div>
                            <div>
                                <h3 class="font-bold">Upload Files</h3>
                                <p class="text-xs text-slate-400">Deploy .py, .js, or .zip</p>
                            </div>
                        </div>
                        <div id="dropZone"
                            class="border-2 border-dashed border-slate-700 rounded-xl p-8 text-center cursor-pointer hover:border-blue-500/70 hover:bg-blue-500/5 transition mb-4"
                            onclick="document.getElementById('fileInput').click()"
                            ondragover="event.preventDefault();this.classList.add('border-blue-500')"
                            ondragleave="this.classList.remove('border-blue-500')"
                            ondrop="handleDrop(event)">
                            <i class="fas fa-file-upload text-4xl text-slate-600 mb-3"></i>
                            <p class="text-slate-300 font-semibold mb-1">Click or drag & drop</p>
                            <p class="text-xs text-slate-500">Python, JavaScript, ZIP — max 100MB</p>
                            <input type="file" id="fileInput" class="hidden" accept=".py,.js,.zip" @change="uploadFile($event)">
                        </div>
                        <div x-show="uploadProgress > 0" class="mb-4">
                            <div class="flex justify-between text-xs mb-1">
                                <span class="text-slate-400">Uploading...</span>
                                <span class="text-blue-400" x-text="uploadProgress+'%'"></span>
                            </div>
                            <div class="bg-slate-800 rounded-full h-1.5">
                                <div class="progress-bar bg-gradient-to-r from-blue-500 to-cyan-500 rounded-full"
                                     :style="'width:'+uploadProgress+'%'"></div>
                            </div>
                        </div>
                        <div class="bg-blue-500/10 border border-blue-500/20 rounded-xl p-3 text-xs text-blue-400">
                            <i class="fas fa-robot mr-2"></i>Cost: <strong>0.5 credits</strong> · AI auto-installs dependencies
                        </div>
                    </div>

                    <!-- GitHub Deploy -->
                    <div class="glass rounded-2xl p-6">
                        <div class="flex items-center gap-3 mb-5">
                            <div class="w-12 h-12 bg-cyan-500/20 rounded-xl flex items-center justify-center">
                                <i class="fab fa-github text-cyan-400 text-xl"></i>
                            </div>
                            <div>
                                <h3 class="font-bold">Deploy from GitHub</h3>
                                <p class="text-xs text-slate-400">Import and deploy repositories</p>
                            </div>
                        </div>
                        <form @submit.prevent="deployGithub()" class="space-y-3">
                            <div>
                                <label class="text-xs font-semibold text-slate-300 mb-1 block">Repository URL *</label>
                                <input type="url" x-model="githubForm.url" required placeholder="https://github.com/user/repo"
                                    class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                            </div>
                            <div class="grid grid-cols-2 gap-3">
                                <div>
                                    <label class="text-xs font-semibold text-slate-300 mb-1 block">Branch</label>
                                    <input type="text" x-model="githubForm.branch" placeholder="main"
                                        class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                                </div>
                                <div>
                                    <label class="text-xs font-semibold text-slate-300 mb-1 block">Build Command</label>
                                    <input type="text" x-model="githubForm.buildCmd" placeholder="npm install"
                                        class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                                </div>
                            </div>
                            <div>
                                <label class="text-xs font-semibold text-slate-300 mb-1 block">Start Command (auto-detected)</label>
                                <input type="text" x-model="githubForm.startCmd" placeholder="npm start"
                                    class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                            </div>
                            <button type="submit" :disabled="deploying"
                                class="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:opacity-90 px-4 py-3 rounded-xl font-bold text-sm transition">
                                <span x-show="!deploying"><i class="fab fa-github mr-2"></i>Deploy from GitHub <span class="opacity-70">(1.0 credit)</span></span>
                                <span x-show="deploying"><i class="fas fa-spinner fa-spin mr-2"></i>Deploying...</span>
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- BUY CREDITS PAGE -->
            <div x-show="currentPage==='buy-credits'" x-transition:enter="transition ease-out duration-200" x-transition:enter-start="opacity-0 translate-y-4" x-transition:enter-end="opacity-100 translate-y-0">
                <h1 class="text-3xl font-black mb-8">Buy Credits</h1>
                <div class="grid md:grid-cols-3 gap-6 mb-8">
                    <div class="glass rounded-2xl p-6 hover:border-blue-500/40 transition cursor-pointer group" @click="selectPackage('10_credits')">
                        <div class="flex justify-between items-start mb-4">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center group-hover:bg-blue-500/30 transition">
                                <i class="fas fa-gem text-blue-400 text-lg"></i>
                            </div>
                            <span class="text-xs bg-blue-500/20 text-blue-400 px-2 py-1 rounded-full font-semibold">STARTER</span>
                        </div>
                        <div class="text-3xl font-black mb-1">10 Credits</div>
                        <div class="text-2xl text-blue-400 font-bold mb-4">₹50</div>
                        <ul class="text-xs text-slate-400 space-y-1.5 mb-6">
                            <li><i class="fas fa-check text-green-400 mr-2"></i>20 File Deployments</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>10 GitHub Deploys</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>20 Backups</li>
                        </ul>
                        <button class="w-full btn-primary py-2.5 rounded-xl text-sm font-semibold">Select Package</button>
                    </div>

                    <div class="relative bg-gradient-to-b from-blue-900/30 to-slate-900 border-2 border-blue-500/50 rounded-2xl p-6 shadow-2xl shadow-blue-500/10">
                        <div class="absolute -top-3.5 left-1/2 -translate-x-1/2 bg-gradient-to-r from-blue-500 to-cyan-500 text-white text-xs font-bold px-4 py-1 rounded-full">BEST VALUE</div>
                        <div class="flex justify-between items-start mb-4">
                            <div class="w-12 h-12 bg-yellow-500/20 rounded-xl flex items-center justify-center">
                                <i class="fas fa-crown text-yellow-400 text-lg"></i>
                            </div>
                            <span class="text-xs bg-blue-500 text-white px-2 py-1 rounded-full font-semibold">PRO</span>
                        </div>
                        <div class="text-3xl font-black mb-1">99 Credits</div>
                        <div class="text-2xl text-blue-400 font-bold mb-0.5">₹399</div>
                        <div class="text-xs text-green-400 mb-4"><s class="text-slate-500">₹495</s> — Save ₹96!</div>
                        <ul class="text-xs text-slate-400 space-y-1.5 mb-6">
                            <li><i class="fas fa-check text-green-400 mr-2"></i>198 File Deployments</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>99 GitHub Deploys</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>198 Backups</li>
                            <li><i class="fas fa-star text-yellow-400 mr-2"></i>Priority Support</li>
                        </ul>
                        <button @click="selectPackage('99_credits')" class="w-full bg-gradient-to-r from-blue-600 to-cyan-500 hover:opacity-90 py-2.5 rounded-xl text-sm font-bold">Select Package</button>
                    </div>

                    <div class="glass rounded-2xl p-6 hover:border-cyan-500/40 transition">
                        <div class="flex justify-between items-start mb-4">
                            <div class="w-12 h-12 bg-cyan-500/20 rounded-xl flex items-center justify-center">
                                <i class="fas fa-infinity text-cyan-400 text-lg"></i>
                            </div>
                            <span class="text-xs bg-cyan-500/20 text-cyan-400 px-2 py-1 rounded-full font-semibold">CUSTOM</span>
                        </div>
                        <div class="text-3xl font-black mb-1">Custom</div>
                        <div class="text-2xl text-cyan-400 font-bold mb-4">Your Amount</div>
                        <div class="mb-4">
                            <label class="text-xs text-slate-400 mb-1 block">Enter amount (₹)</label>
                            <input type="number" x-model="customAmount" placeholder="e.g. 200" min="10"
                                class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500">
                        </div>
                        <p class="text-xs text-slate-400 mb-4">
                            Need help? <a href="{{ telegram_link }}" target="_blank" class="text-blue-400 hover:underline">Contact {{ username }}</a>
                        </p>
                        <button @click="selectCustomPackage()" class="w-full bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-400 border border-cyan-600/30 py-2.5 rounded-xl text-sm font-semibold transition">
                            <i class="fas fa-paper-plane mr-2"></i>Proceed
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Payment Modal -->
    <div x-show="modal==='payment'" x-cloak @click.self="modal=null"
         class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
        <div class="glass rounded-2xl max-w-md w-full p-6 max-h-[90vh] overflow-y-auto">
            <div class="flex items-center justify-between mb-6">
                <h2 class="text-xl font-black">Complete Payment</h2>
                <button @click="modal=null" class="text-slate-400 hover:text-white">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="bg-slate-800/50 rounded-xl p-4 mb-4 text-sm space-y-2">
                <div class="flex justify-between"><span class="text-slate-400">Package</span><span class="font-bold" x-text="paymentData.package"></span></div>
                <div class="flex justify-between"><span class="text-slate-400">Credits</span><span class="text-blue-400 font-bold" x-text="paymentData.credits"></span></div>
                <div class="flex justify-between"><span class="text-slate-400">Amount</span><span class="text-green-400 text-xl font-black">₹<span x-text="paymentData.price"></span></span></div>
            </div>
            <div class="bg-white rounded-xl p-3 mb-4 text-center">
                <img src="/qr.jpg" alt="QR" class="w-56 h-56 mx-auto object-contain">
                <p class="text-slate-900 font-bold text-sm mt-2">Scan · Pay ₹<span x-text="paymentData.price"></span></p>
            </div>
            <div class="space-y-3 mb-4">
                <div>
                    <label class="text-xs font-semibold text-slate-300 mb-1 block">Payment Screenshot</label>
                    <input type="file" accept="image/*" @change="uploadScreenshot($event)"
                        class="w-full text-sm text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:bg-blue-600 file:text-white file:text-xs cursor-pointer">
                </div>
                <div>
                    <label class="text-xs font-semibold text-slate-300 mb-1 block">Transaction / UTR ID</label>
                    <input type="text" x-model="paymentData.transactionId" placeholder="Enter transaction ID" required
                        class="w-full px-4 py-2.5 bg-slate-800 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
            </div>
            <div class="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-3 text-xs text-yellow-400 mb-4 flex items-center gap-2">
                <i class="fas fa-clock"></i>
                <span>Time remaining: <strong x-text="formatTime(timeRemaining)"></strong></span>
            </div>
            <div class="flex gap-3">
                <button @click="modal=null" class="flex-1 bg-slate-700 hover:bg-slate-600 py-3 rounded-xl text-sm transition">Cancel</button>
                <button @click="submitPayment()" class="flex-1 btn-primary py-3 rounded-xl text-sm font-bold">
                    <i class="fas fa-check mr-1"></i>Submit
                </button>
            </div>
        </div>
    </div>

    <!-- Deployment Details Modal -->
    <div x-show="modal==='details'" x-cloak @click.self="modal=null"
         class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
        <div class="glass rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div class="sticky top-0 bg-slate-900/95 backdrop-blur p-6 border-b border-slate-800 flex items-center justify-between z-10">
                <div>
                    <h2 class="text-xl font-black" x-text="selectedDeploy && selectedDeploy.name"></h2>
                    <p class="text-xs text-slate-400" x-text="selectedDeploy && selectedDeploy.id"></p>
                </div>
                <button @click="modal=null" class="text-slate-400 hover:text-white p-2">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
            <div class="p-6" x-show="selectedDeploy">
                <!-- Tabs -->
                <div class="flex gap-1 mb-6 bg-slate-800/50 p-1 rounded-xl flex-wrap">
                    <template x-for="tab in ['info','env','files','backup','console']" :key="tab">
                        <button @click="detailsTab=tab"
                            :class="detailsTab===tab ? 'bg-blue-600 text-white shadow' : 'text-slate-400 hover:text-white'"
                            class="flex-1 px-4 py-2 rounded-lg text-xs font-semibold capitalize transition min-w-[60px]"
                            x-text="tab"></button>
                    </template>
                </div>

                <div x-show="detailsTab==='info'" class="space-y-4">
                    <div class="grid grid-cols-2 gap-3">
                        <template x-for="[label, val] in [['ID', selectedDeploy?.id],['Port', selectedDeploy?.port],['Status', selectedDeploy?.status],['Type', selectedDeploy?.type],['PID', selectedDeploy?.pid],['Restarts', selectedDeploy?.restart_count]]" :key="label">
                            <div class="bg-slate-800/40 rounded-xl p-3">
                                <div class="text-xs text-slate-400 mb-1" x-text="label"></div>
                                <div class="font-mono text-sm font-semibold" x-text="val"></div>
                            </div>
                        </template>
                    </div>
                    <div x-show="selectedDeploy?.dependencies?.length > 0">
                        <p class="text-xs font-semibold text-slate-300 mb-2">AI-Installed Dependencies</p>
                        <div class="flex flex-wrap gap-2">
                            <template x-for="dep in selectedDeploy?.dependencies" :key="dep">
                                <span class="bg-blue-500/20 text-blue-300 border border-blue-500/20 px-3 py-1 rounded-full text-xs" x-text="dep"></span>
                            </template>
                        </div>
                    </div>
                </div>

                <div x-show="detailsTab==='env'">
                    <div class="flex gap-2 mb-4">
                        <input x-model="newEnv.key" placeholder="KEY" class="flex-1 px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <input x-model="newEnv.value" placeholder="value" class="flex-1 px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <button @click="addEnvVar()" class="btn-primary px-4 py-2 rounded-xl text-sm">
                            <i class="fas fa-plus"></i>
                        </button>
                    </div>
                    <div class="space-y-2">
                        <template x-for="[k, v] in Object.entries(selectedDeploy?.env_vars || {})" :key="k">
                            <div class="bg-slate-800/40 rounded-xl p-3 flex items-center justify-between">
                                <div class="font-mono text-sm"><span class="text-blue-400" x-text="k"></span> = <span x-text="v"></span></div>
                                <button @click="deleteEnvVar(k)" class="text-red-400 hover:text-red-300 px-2"><i class="fas fa-trash text-xs"></i></button>
                            </div>
                        </template>
                        <div x-show="!selectedDeploy?.env_vars || Object.keys(selectedDeploy?.env_vars).length===0" class="text-center py-8 text-slate-400 text-sm">No env vars set</div>
                    </div>
                </div>

                <div x-show="detailsTab==='files'">
                    <button @click="loadFiles()" class="btn-primary px-4 py-2 rounded-xl text-sm mb-4">
                        <i class="fas fa-sync mr-2"></i>Refresh
                    </button>
                    <div class="space-y-2 max-h-80 overflow-y-auto">
                        <template x-for="file in deployFiles" :key="file.path">
                            <div class="bg-slate-800/40 rounded-xl p-3 flex items-center justify-between">
                                <div class="flex items-center gap-3">
                                    <i class="fas fa-file-code text-slate-400 text-sm"></i>
                                    <div>
                                        <div class="font-mono text-sm" x-text="file.path"></div>
                                        <div class="text-xs text-slate-500" x-text="formatBytes(file.size)"></div>
                                    </div>
                                </div>
                                <div class="text-xs text-slate-400" x-text="formatDate(file.modified)"></div>
                            </div>
                        </template>
                        <div x-show="deployFiles.length===0" class="text-center py-8 text-slate-400 text-sm">No files found</div>
                    </div>
                </div>

                <div x-show="detailsTab==='backup'" class="text-center py-10">
                    <i class="fas fa-archive text-6xl text-slate-700 mb-4"></i>
                    <h3 class="text-xl font-bold mb-2">Create Backup</h3>
                    <p class="text-slate-400 text-sm mb-6">Download a complete snapshot of this deployment</p>
                    <button @click="createBackup()" class="btn-primary px-8 py-3 rounded-xl font-semibold">
                        <i class="fas fa-download mr-2"></i>Create & Download Backup <span class="opacity-70">(0.5 cr)</span>
                    </button>
                </div>

                <div x-show="detailsTab==='console'">
                    <div class="bg-slate-950 rounded-xl p-4 font-mono text-xs text-green-400 h-80 overflow-y-auto whitespace-pre-wrap leading-relaxed border border-slate-800"
                         x-ref="consoleEl" x-text="consoleLogs"></div>
                    <div class="flex gap-2 mt-3">
                        <button @click="refreshLogs()" class="btn-primary px-4 py-2 rounded-xl text-sm">
                            <i class="fas fa-sync mr-2"></i>Refresh
                        </button>
                        <button @click="consoleLogs=''" class="bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded-xl text-sm transition">
                            Clear
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
    // ==================== DROP HANDLER ====================
    function handleDrop(e) {
        e.preventDefault();
        document.getElementById('dropZone').classList.remove('border-blue-500');
        const file = e.dataTransfer.files[0];
        if (file) {
            Alpine.store && Alpine.store('app');
            const input = document.getElementById('fileInput');
            const dt = new DataTransfer();
            dt.items.add(file);
            input.files = dt.files;
            input.dispatchEvent(new Event('change'));
        }
    }

    // ==================== ALPINE APP ====================
    function dashApp() {
        return {
            sidebarOpen: false,
            currentPage: 'overview',
            modal: null,
            detailsTab: 'info',
            credits: {{ credits }},
            deployments: [],
            stats: { total: 0, running: 0 },
            selectedDeploy: null,
            deployFiles: [],
            consoleLogs: '',
            deploying: false,
            uploadProgress: 0,
            githubForm: { url: '', branch: 'main', buildCmd: '', startCmd: '' },
            newEnv: { key: '', value: '' },
            customAmount: '',
            paymentData: { id:'', package:'', credits:0, price:0, screenshot:null, transactionId:'' },
            timeRemaining: 1800,   // 30 minutes
            timerInterval: null,
            navItems: [
                { id:'overview', icon:'fas fa-th-large', label:'Overview', badge:0 },
                { id:'deployments', icon:'fas fa-rocket', label:'Deployments', badge:0 },
                { id:'new-deploy', icon:'fas fa-plus-circle', label:'New Deploy', badge:0 },
                { id:'buy-credits', icon:'fas fa-gem', label:'Buy Credits', badge:0 },
            ],
            sseConnected: false,
            sseRetries: 0,

            // ─────────────────────────────────────────────────
            init() {
                this.loadDeployments();
                this.connectSSE();
                setInterval(() => this.loadDeployments(), 30000);
            },

            navigate(page) {
                this.currentPage = page;
                this.sidebarOpen = false;
            },

            connectSSE() {
                if (typeof EventSource === 'undefined') return;
                const es = new EventSource('/api/events');
                es.onopen = () => { this.sseConnected = true; this.sseRetries = 0; };
                es.onmessage = (e) => {
                    try {
                        const event = JSON.parse(e.data);
                        this.handleSSEEvent(event);
                    } catch (err) {}
                };
                es.onerror = () => {
                    es.close();
                    this.sseConnected = false;
                    const delay = Math.min(30000, 1000 * Math.pow(2, this.sseRetries++));
                    setTimeout(() => this.connectSSE(), delay);
                };
            },

            handleSSEEvent(event) {
                switch(event.type) {
                    case 'deployment_updated':
                        this.loadDeployments(); break;
                    case 'credits_updated':
                        this.credits = event.data.credits; break;
                    case 'payment_approved':
                        this.showToast(`💎 Payment approved! +${event.data.credits} credits`, 'success');
                        this.credits = (parseFloat(this.credits) + event.data.credits).toFixed(1);
                        break;
                    case 'payment_rejected':
                        this.showToast('❌ Payment was rejected. Please contact support.', 'error'); break;
                }
            },

            async loadDeployments(force=false) {
                try {
                    const res = await fetch('/api/deployments');
                    if (res.status === 429 && !force) return;
                    const data = await res.json();
                    if (data.success) {
                        this.deployments = data.deployments;
                        this.stats.total = data.deployments.length;
                        this.stats.running = data.deployments.filter(d => d.status==='running').length;
                        this.navItems[1].badge = this.stats.running || 0;
                    }
                } catch(e) { console.warn('Deploy poll:', e.message); }
            },

            async uploadFile(event) {
                const file = event.target.files[0];
                if (!file) return;
                const formData = new FormData();
                formData.append('file', file);
                this.uploadProgress = 10;
                const progressInterval = setInterval(() => {
                    if (this.uploadProgress < 85) this.uploadProgress += 5;
                }, 400);
                try {
                    const res = await fetch('/api/deploy/upload', { method:'POST', body:formData });
                    clearInterval(progressInterval);
                    this.uploadProgress = 100;
                    const data = await res.json();
                    setTimeout(() => { this.uploadProgress = 0; }, 1000);
                    if (data.success) {
                        this.showToast('✅ Deployment successful!', 'success');
                        this.loadDeployments();
                        this.currentPage = 'deployments';
                    } else {
                        this.showToast('❌ ' + data.error, 'error');
                    }
                } catch(e) {
                    clearInterval(progressInterval);
                    this.uploadProgress = 0;
                    this.showToast('❌ Upload failed', 'error');
                }
                event.target.value = '';
            },

            async deployGithub() {
                if (!this.githubForm.url) return;
                this.deploying = true;
                try {
                    const res = await fetch('/api/deploy/github', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({
                            url: this.githubForm.url, branch: this.githubForm.branch || 'main',
                            build_command: this.githubForm.buildCmd, start_command: this.githubForm.startCmd
                        })
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.showToast('✅ GitHub deployment successful!', 'success');
                        this.loadDeployments();
                        this.currentPage = 'deployments';
                        this.githubForm = { url:'', branch:'main', buildCmd:'', startCmd:'' };
                    } else {
                        this.showToast('❌ ' + data.error, 'error');
                    }
                } catch(e) { this.showToast('❌ Deployment failed', 'error'); }
                finally { this.deploying = false; }
            },

            async selectPackage(packageType) {
                try {
                    const res = await fetch('/api/payment/create', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({ package_type: packageType })
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.paymentData = { ...data.payment, package: packageType.replace('_',' ').toUpperCase(), screenshot:null, transactionId:'' };
                        this.modal = 'payment';
                        this.startTimer(data.payment.expires_at);
                    } else { this.showToast('❌ ' + data.error, 'error'); }
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },

            async selectCustomPackage() {
                if (!this.customAmount || this.customAmount < 10) {
                    this.showToast('❌ Minimum amount is ₹10', 'error'); return;
                }
                try {
                    const res = await fetch('/api/payment/create', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({ package_type:'custom', custom_amount: parseInt(this.customAmount) })
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.paymentData = { ...data.payment, package:'CUSTOM', screenshot:null, transactionId:'' };
                        this.modal = 'payment';
                        this.startTimer(data.payment.expires_at);
                    } else { this.showToast('❌ ' + data.error, 'error'); }
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },

            uploadScreenshot(event) {
                const file = event.target.files[0];
                if (!file) return;
                const reader = new FileReader();
                reader.onload = (e) => { this.paymentData.screenshot = e.target.result; };
                reader.readAsDataURL(file);
            },

            async submitPayment() {
                if (!this.paymentData.screenshot) { this.showToast('❌ Upload screenshot', 'error'); return; }
                if (!this.paymentData.transactionId) { this.showToast('❌ Enter transaction ID', 'error'); return; }
                try {
                    const res = await fetch('/api/payment/submit', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({ payment_id:this.paymentData.id, screenshot:this.paymentData.screenshot, transaction_id:this.paymentData.transactionId })
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.stopTimer(); this.modal = null;
                        this.showToast('✅ Payment submitted! Awaiting admin approval.', 'success');
                    } else { this.showToast('❌ ' + data.error, 'error'); }
                } catch(e) { this.showToast('❌ Submission failed', 'error'); }
            },

            startTimer(expiresAt) {
                this.stopTimer();
                const expires = new Date(expiresAt).getTime();
                this.timerInterval = setInterval(() => {
                    this.timeRemaining = Math.max(0, Math.round((expires - Date.now()) / 1000));
                    if (this.timeRemaining <= 0) {
                        this.stopTimer(); this.modal = null;
                        this.showToast('⏰ Payment session expired', 'error');
                    }
                }, 1000);
                this.timeRemaining = Math.max(0, Math.round((expires - Date.now()) / 1000));
            },

            stopTimer() { if (this.timerInterval) { clearInterval(this.timerInterval); this.timerInterval = null; } },

            formatTime(s) {
                const m = Math.floor(s/60), sec = s%60;
                return `${m}:${String(sec).padStart(2,'0')}`;
            },

            viewDeployment(id) {
                this.selectedDeploy = this.deployments.find(d=>d.id===id);
                this.modal = 'details'; this.detailsTab = 'info';
            },
            viewLogs(id) {
                this.selectedDeploy = this.deployments.find(d=>d.id===id);
                this.modal = 'details'; this.detailsTab = 'console'; this.refreshLogs();
            },
            async refreshLogs() {
                if (!this.selectedDeploy) return;
                try {
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/logs`);
                    const data = await res.json();
                    this.consoleLogs = data.logs || 'No logs available';
                    this.$nextTick(() => { if (this.$refs.consoleEl) this.$refs.consoleEl.scrollTop = 999999; });
                } catch(e) { this.consoleLogs = 'Failed to load logs'; }
            },
            async loadFiles() {
                if (!this.selectedDeploy) return;
                try {
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/files`);
                    const data = await res.json();
                    this.deployFiles = data.files || [];
                } catch(e) { this.deployFiles = []; }
            },
            async addEnvVar() {
                if (!this.newEnv.key || !this.newEnv.value) return;
                try {
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/env`, {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify(this.newEnv)
                    });
                    const data = await res.json();
                    if (data.success) { this.selectedDeploy.env_vars = data.env_vars; this.newEnv={key:'',value:''}; this.showToast('✅ Env var added', 'success'); }
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            async deleteEnvVar(key) {
                try {
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/env/${key}`, { method:'DELETE' });
                    const data = await res.json();
                    if (data.success) { this.selectedDeploy.env_vars = data.env_vars; this.showToast('✅ Deleted', 'success'); }
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            async createBackup() {
                if (!confirm('Create backup for 0.5 credits?')) return;
                try {
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/backup`, { method:'POST' });
                    const data = await res.json();
                    if (data.success) {
                        window.location.href = `/api/deployment/${this.selectedDeploy.id}/backup/download`;
                        this.showToast('✅ Backup created!', 'success');
                    } else { this.showToast('❌ ' + data.error, 'error'); }
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            async stopDeploy(id) {
                if (!confirm('Stop this deployment?')) return;
                try {
                    const res = await fetch(`/api/deployment/${id}/stop`, { method:'POST' });
                    const data = await res.json();
                    this.showToast(data.success ? '🛑 Deployment stopped' : '❌ '+data.error, data.success?'info':'error');
                    this.loadDeployments();
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            async restartDeploy(id) {
                try {
                    const res = await fetch(`/api/deployment/${id}/restart`, { method:'POST' });
                    const data = await res.json();
                    this.showToast(data.success ? '🔄 Restarting...' : '❌ '+data.error, data.success?'info':'error');
                    setTimeout(() => this.loadDeployments(), 3000);
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            async deleteDeploy(id) {
                if (!confirm('Permanently delete this deployment?')) return;
                try {
                    const res = await fetch(`/api/deployment/${id}`, { method:'DELETE' });
                    const data = await res.json();
                    this.showToast(data.success ? '🗑️ Deleted' : '❌ '+data.error, data.success?'success':'error');
                    this.loadDeployments(); this.modal = null;
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            logout() { if (confirm('Logout?')) window.location.href = '/logout'; },

            showToast(msg, type='info') {
                const colors = { success:'bg-green-600', error:'bg-red-600', info:'bg-blue-600' };
                const container = document.getElementById('toastContainer') || document.body;
                const el = document.createElement('div');
                el.className = `toast ${colors[type]||'bg-blue-600'} text-white px-5 py-3 rounded-2xl shadow-2xl text-sm font-semibold flex items-center gap-2 mb-2`;
                el.innerHTML = msg;
                container.appendChild(el);
                setTimeout(() => { el.style.opacity='0'; el.style.transition='opacity 0.5s'; setTimeout(()=>el.remove(), 500); }, 3500);
            },

            formatBytes(b) {
                if(!b) return '0 B';
                const k=1024, sizes=['B','KB','MB','GB'];
                const i=Math.floor(Math.log(b)/Math.log(k));
                return (b/Math.pow(k,i)).toFixed(1)+' '+sizes[i];
            },
            formatDate(d) { return new Date(d).toLocaleString(); }
        }
    }
    </script>
</body>
</html>"""

ADMIN_PANEL_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost v14 - Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        body{background:#060d1a}
        .glass{background:rgba(15,23,42,0.8);backdrop-filter:blur(16px);border:1px solid rgba(59,130,246,0.1)}
        ::-webkit-scrollbar{width:4px;height:4px}
        ::-webkit-scrollbar-thumb{background:#1e40af;border-radius:2px}
    </style>
</head>
<body class="text-white min-h-screen" x-data="adminApp()">
    <div class="bg-gradient-to-r from-blue-900 to-cyan-900 p-6 shadow-2xl">
        <div class="max-w-7xl mx-auto flex items-center justify-between">
            <div class="flex items-center gap-4">
                <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center">
                    <i class="fas fa-crown text-white text-xl"></i>
                </div>
                <div>
                    <h1 class="text-2xl font-black">Admin Control Panel</h1>
                    <p class="text-blue-200 text-xs">EliteHost v14.0 — Full System Control</p>
                </div>
            </div>
            <div class="flex gap-3">
                <a href="/dashboard" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-xl text-sm transition">
                    <i class="fas fa-arrow-left mr-2"></i>Dashboard
                </a>
                <button @click="location.reload()" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-xl text-sm transition">
                    <i class="fas fa-sync mr-2"></i>Refresh
                </button>
            </div>
        </div>
    </div>

    <div class="max-w-7xl mx-auto p-6">
        <!-- Stats -->
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <div class="glass rounded-2xl p-5"><div class="text-3xl font-black mb-1">{{ stats.total_users }}</div><div class="text-slate-400 text-xs">Total Users</div></div>
            <div class="glass rounded-2xl p-5"><div class="text-3xl font-black mb-1 text-blue-400">{{ stats.total_deployments }}</div><div class="text-slate-400 text-xs">Total Deployments</div></div>
            <div class="glass rounded-2xl p-5"><div class="text-3xl font-black mb-1 text-green-400">{{ stats.active_processes }}</div><div class="text-slate-400 text-xs">Active Processes</div></div>
            <div class="glass rounded-2xl p-5"><div class="text-3xl font-black mb-1 text-yellow-400">{{ stats.pending_payments }}</div><div class="text-slate-400 text-xs">Pending Payments</div></div>
        </div>

        <!-- System Metrics -->
        <div class="glass rounded-2xl p-6 mb-8">
            <h2 class="text-lg font-bold mb-5">System Resources</h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <template x-for="[label, key, color] in [['CPU Usage','cpu','bg-blue-500'],['Memory','memory_percent','bg-green-500'],['Disk','disk_percent','bg-cyan-500']]" :key="key">
                    <div>
                        <div class="flex justify-between text-sm mb-2">
                            <span class="text-slate-400" x-text="label"></span>
                            <span class="font-bold" x-text="(metrics[key]||0)+'%'"></span>
                        </div>
                        <div class="bg-slate-800 rounded-full h-2">
                            <div :class="color" class="h-2 rounded-full transition-all duration-1000"
                                 :style="'width:'+(metrics[key]||0)+'%'"></div>
                        </div>
                    </div>
                </template>
            </div>
            <div class="grid grid-cols-3 gap-4 mt-4 text-xs text-slate-400">
                <div>RAM: <span class="text-white font-semibold" x-text="(metrics.memory_used||0)+'/'+( metrics.memory_total||0)+' GB'"></span></div>
                <div>Disk: <span class="text-white font-semibold" x-text="(metrics.disk_used||0)+'/'+(metrics.disk_total||0)+' GB'"></span></div>
                <div>Net: <span class="text-white font-semibold" x-text="'↑'+(metrics.net_sent_mb||0)+' MB ↓'+(metrics.net_recv_mb||0)+' MB'"></span></div>
            </div>
        </div>

        <!-- Users -->
        <div class="glass rounded-2xl mb-8 overflow-hidden">
            <div class="p-5 border-b border-slate-800 flex items-center justify-between">
                <h2 class="text-lg font-bold">Users</h2>
                <span class="text-xs text-slate-400">{{ users|length }} total</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead class="bg-slate-800/50 text-xs text-slate-400">
                        <tr>
                            <th class="text-left p-4">Email</th>
                            <th class="text-left p-4">Credits</th>
                            <th class="text-left p-4">Deploys</th>
                            <th class="text-left p-4">Joined</th>
                            <th class="text-left p-4">Status</th>
                            <th class="text-left p-4">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for user in users %}
                        <tr class="border-b border-slate-800/50 hover:bg-slate-800/20 transition">
                            <td class="p-4 font-medium">{{ user.email }}</td>
                            <td class="p-4 font-mono text-blue-400">{{ user.credits }}</td>
                            <td class="p-4">{{ user.deployments|length }}</td>
                            <td class="p-4 text-slate-400">{{ user.created_at[:10] }}</td>
                            <td class="p-4">
                                {% if user.is_banned %}
                                <span class="px-2 py-1 bg-red-500/20 text-red-400 rounded-lg text-xs font-bold">BANNED</span>
                                {% else %}
                                <span class="px-2 py-1 bg-green-500/20 text-green-400 rounded-lg text-xs font-bold">ACTIVE</span>
                                {% endif %}
                            </td>
                            <td class="p-4">
                                <div class="flex gap-2">
                                    <button onclick="addCreditsPrompt('{{ user.id }}')"
                                        class="bg-green-600/20 hover:bg-green-600/30 text-green-400 px-3 py-1.5 rounded-lg text-xs font-semibold transition">
                                        <i class="fas fa-plus mr-1"></i>Credits
                                    </button>
                                    {% if not user.is_banned %}
                                    <button onclick="banUser('{{ user.id }}')"
                                        class="bg-red-600/20 hover:bg-red-600/30 text-red-400 px-3 py-1.5 rounded-lg text-xs font-semibold transition">
                                        <i class="fas fa-ban mr-1"></i>Ban
                                    </button>
                                    {% else %}
                                    <button onclick="unbanUser('{{ user.id }}')"
                                        class="bg-green-600/20 hover:bg-green-600/30 text-green-400 px-3 py-1.5 rounded-lg text-xs font-semibold transition">
                                        <i class="fas fa-check mr-1"></i>Unban
                                    </button>
                                    {% endif %}
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Payments -->
        <div class="glass rounded-2xl overflow-hidden">
            <div class="p-5 border-b border-slate-800 flex items-center justify-between">
                <h2 class="text-lg font-bold">Payment Requests</h2>
                <span class="text-xs text-slate-400">{{ payments|length }} total</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead class="bg-slate-800/50 text-xs text-slate-400">
                        <tr>
                            <th class="text-left p-4">User</th>
                            <th class="text-left p-4">Amount</th>
                            <th class="text-left p-4">Transaction ID</th>
                            <th class="text-left p-4">Date</th>
                            <th class="text-left p-4">Status</th>
                            <th class="text-left p-4">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for p in payments %}
                        <tr class="border-b border-slate-800/50 hover:bg-slate-800/20 transition">
                            <td class="p-4">{{ p.user_email }}</td>
                            <td class="p-4 font-mono text-blue-400">{{ p.credits }} cr (₹{{ p.price }})</td>
                            <td class="p-4 font-mono text-xs">{{ p.transaction_id or '—' }}</td>
                            <td class="p-4 text-slate-400 text-xs">{{ p.created_at[:16] }}</td>
                            <td class="p-4">
                                <span class="px-2 py-1 rounded-lg text-xs font-bold
                                    {% if p.status == 'approved' %}bg-green-500/20 text-green-400
                                    {% elif p.status == 'submitted' %}bg-blue-500/20 text-blue-400
                                    {% elif p.status == 'pending' %}bg-yellow-500/20 text-yellow-400
                                    {% elif p.status == 'expired' %}bg-gray-500/20 text-gray-400
                                    {% else %}bg-red-500/20 text-red-400{% endif %}">
                                    {{ p.status.upper() }}
                                </span>
                            </td>
                            <td class="p-4">
                                {% if p.status == 'submitted' %}
                                <div class="flex gap-2">
                                    <button onclick="approvePayment('{{ p.id }}','{{ p.user_id }}',{{ p.credits }})"
                                        class="bg-green-600/20 hover:bg-green-600/30 text-green-400 px-3 py-1.5 rounded-lg text-xs font-bold transition">
                                        ✅ Approve
                                    </button>
                                    <button onclick="rejectPayment('{{ p.id }}')"
                                        class="bg-red-600/20 hover:bg-red-600/30 text-red-400 px-3 py-1.5 rounded-lg text-xs font-bold transition">
                                        ❌ Reject
                                    </button>
                                    <button onclick="viewScreenshot('{{ p.id }}')"
                                        class="bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 px-3 py-1.5 rounded-lg text-xs font-bold transition">
                                        🖼 View
                                    </button>
                                </div>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        function adminApp() {
            return {
                metrics: {},
                init() { this.loadMetrics(); setInterval(() => this.loadMetrics(), 5000); },
                async loadMetrics() {
                    try {
                        const r = await fetch('/api/admin/metrics');
                        const d = await r.json();
                        if (d.success) this.metrics = d.metrics;
                    } catch(e) {}
                }
            }
        }

        async function addCreditsPrompt(userId) {
            const amt = prompt('Credits to add:');
            if (!amt || isNaN(amt) || parseFloat(amt) <= 0) return;
            const r = await fetch('/api/admin/add-credits', {
                method:'POST', headers:{'Content-Type':'application/json'},
                body: JSON.stringify({ user_id: userId, amount: parseFloat(amt) })
            });
            const d = await r.json();
            alert(d.success ? '✅ Credits added!' : '❌ ' + d.error);
            if (d.success) location.reload();
        }

        async function approvePayment(paymentId, userId, credits) {
            if (!confirm(`Approve payment and add ${credits} credits?`)) return;
            const r = await fetch('/api/admin/approve-payment', {
                method:'POST', headers:{'Content-Type':'application/json'},
                body: JSON.stringify({ payment_id: paymentId })
            });
            const d = await r.json();
            alert(d.success ? '✅ Approved!' : '❌ ' + d.error);
            if (d.success) location.reload();
        }

        async function rejectPayment(paymentId) {
            if (!confirm('Reject this payment?')) return;
            const r = await fetch('/api/admin/reject-payment', {
                method:'POST', headers:{'Content-Type':'application/json'},
                body: JSON.stringify({ payment_id: paymentId })
            });
            const d = await r.json();
            alert(d.success ? '✅ Rejected' : '❌ ' + d.error);
            if (d.success) location.reload();
        }

        async function banUser(userId) {
            if (!confirm('Ban this user?')) return;
            await fetch('/api/admin/ban-user', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({user_id:userId, ban:true}) });
            location.reload();
        }
        async function unbanUser(userId) {
            if (!confirm('Unban this user?')) return;
            await fetch('/api/admin/ban-user', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({user_id:userId, ban:false}) });
            location.reload();
        }
        function viewScreenshot(id) { window.open(`/api/payment/${id}/screenshot`, '_blank'); }
    </script>
</body>
</html>"""
