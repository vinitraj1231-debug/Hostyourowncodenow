# DASHBOARD_HTML template for EliteHost v13.0
# This should be inserted into the main Python file

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost  - Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        primary: '#3b82f6',
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-slate-950 text-white" x-data="dashboardApp()">
    <!-- Sidebar -->
    <div class="fixed inset-y-0 left-0 w-64 bg-slate-900 border-r border-slate-800 z-50 transform transition-transform duration-300"
         :class="sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'">
        <div class="p-6">
            <div class="flex items-center gap-3 mb-8">
                <img src="/logo.jpg" alt="Logo" class="w-10 h-10 rounded-lg">
                <span class="text-xl font-bold">EliteHost v13</span>
            </div>
            
            <nav class="space-y-1">
                <button @click="sidebarOpen = false" 
                        class="md:hidden w-full flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-slate-800 cursor-pointer transition text-slate-400 hover:text-white mb-2 group">
                    <i class="fas fa-times w-5"></i>
                    <span>Close Menu</span>
                </button>
                <div class="h-px bg-slate-800 mx-4 mb-2 md:hidden"></div>
                
                <a @click="currentPage = 'overview'; sidebarOpen = false" :class="currentPage === 'overview' ? 'bg-blue-600' : 'hover:bg-slate-800'"
                   class="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition">
                    <i class="fas fa-th-large w-5"></i>
                    <span>Overview</span>
                </a>
                <a @click="currentPage = 'deployments'; sidebarOpen = false" :class="currentPage === 'deployments' ? 'bg-blue-600' : 'hover:bg-slate-800'"
                   class="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition">
                    <i class="fas fa-rocket w-5"></i>
                    <span>Deployments</span>
                </a>
                <a @click="currentPage = 'new-deploy'; sidebarOpen = false" :class="currentPage === 'new-deploy' ? 'bg-blue-600' : 'hover:bg-slate-800'"
                   class="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition">
                    <i class="fas fa-plus-circle w-5"></i>
                    <span>New Deploy</span>
                </a>
                <a @click="currentPage = 'buy-credits'; sidebarOpen = false" :class="currentPage === 'buy-credits' ? 'bg-blue-600' : 'hover:bg-slate-800'"
                   class="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition">
                    <i class="fas fa-gem w-5"></i>
                    <span>Buy Credits</span>
                </a>
                <a @click="currentPage = 'analytics'; sidebarOpen = false" :class="currentPage === 'analytics' ? 'bg-blue-600' : 'hover:bg-slate-800'"
                   class="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition">
                    <i class="fas fa-chart-line w-5"></i>
                    <span>Analytics</span>
                </a>
                <a @click="currentPage = 'api-keys'; sidebarOpen = false" :class="currentPage === 'api-keys' ? 'bg-blue-600' : 'hover:bg-slate-800'"
                   class="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition">
                    <i class="fas fa-key w-5"></i>
                    <span>API Keys</span>
                </a>
                <a @click="currentPage = 'referrals'; sidebarOpen = false" :class="currentPage === 'referrals' ? 'bg-blue-600' : 'hover:bg-slate-800'"
                   class="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition">
                    <i class="fas fa-gift w-5"></i>
                    <span>Referrals</span>
                </a>
                {% if is_admin %}
                <a href="/admin" class="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-slate-800 cursor-pointer transition">
                    <i class="fas fa-crown w-5 text-yellow-500"></i>
                    <span>Admin Panel</span>
                </a>
                {% endif %}
            </nav>
        </div>
        
        <div class="absolute bottom-0 left-0 right-0 p-6 border-t border-slate-800">
            <div class="bg-gradient-to-r from-blue-600 to-blue-700 rounded-lg p-4 mb-4">
                <div class="flex items-center justify-between mb-2">
                    <span class="text-sm font-semibold">Credits</span>
                    <i class="fas fa-gem"></i>
                </div>
                <div class="text-2xl font-bold" x-text="credits"></div>
            </div>
            <button @click="logout()" class="w-full bg-red-600/20 hover:bg-red-600/30 text-red-400 px-4 py-2 rounded-lg transition">
                <i class="fas fa-sign-out-alt mr-2"></i>Logout
            </button>
        </div>
    </div>
    
    <!-- Mobile Header -->
    <div class="md:hidden fixed top-0 left-0 right-0 bg-slate-900 border-b border-slate-800 p-4 z-40 flex items-center justify-between">
        <button @click="sidebarOpen = !sidebarOpen" class="text-white">
            <i class="fas fa-bars text-xl"></i>
        </button>
        <img src="/logo.jpg" alt="Logo" class="w-8 h-8 rounded-lg">
        <div class="w-6"></div>
    </div>
    
    <!-- Main Content -->
    <div class="md:ml-64 min-h-screen">
        <div class="p-4 md:p-8 mt-16 md:mt-0">
            <!-- Overview Page -->
            <div x-show="currentPage === 'overview'" x-transition>
                <h1 class="text-3xl font-bold mb-8">Dashboard Overview</h1>
                
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                        <div class="flex items-center justify-between mb-4">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-rocket text-blue-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1" x-text="stats.total"></div>
                        <div class="text-slate-400 text-sm">Total Deployments</div>
                    </div>
                    
                    <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                        <div class="flex items-center justify-between mb-4">
                            <div class="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-check-circle text-green-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1 text-green-400" x-text="stats.running"></div>
                        <div class="text-slate-400 text-sm">Active Now</div>
                    </div>
                    
                    <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                        <div class="flex items-center justify-between mb-4">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-gem text-blue-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1 text-blue-400" x-text="credits"></div>
                        <div class="text-slate-400 text-sm">Available Credits</div>
                    </div>
                    
                    <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                        <div class="flex items-center justify-between mb-4">
                            <div class="w-12 h-12 bg-cyan-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-robot text-cyan-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1">AI</div>
                        <div class="text-slate-400 text-sm">Auto Deploy</div>
                    </div>
                </div>
                
                <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                    <h2 class="text-xl font-bold mb-4">Recent Deployments</h2>
                    <div class="space-y-3" x-show="deployments.length > 0">
                        <template x-for="deploy in deployments.slice(0, 5)" :key="deploy.id">
                            <div class="bg-slate-800/50 rounded-lg p-4 flex items-center justify-between">
                                <div class="flex items-center gap-4">
                                    <div class="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                        <i class="fas fa-rocket text-blue-400"></i>
                                    </div>
                                    <div>
                                        <div class="font-semibold" x-text="deploy.name"></div>
                                        <div class="text-sm text-slate-400">
                                            <span x-text="deploy.id"></span> • Port <span x-text="deploy.port"></span>
                                        </div>
                                    </div>
                                </div>
                                <span class="px-3 py-1 rounded-full text-xs font-semibold"
                                      :class="{
                                          'bg-green-500/20 text-green-400': deploy.status === 'running',
                                          'bg-yellow-500/20 text-yellow-400': deploy.status === 'pending',
                                          'bg-red-500/20 text-red-400': deploy.status === 'stopped'
                                      }"
                                      x-text="deploy.status"></span>
                            </div>
                        </template>
                    </div>
                    <div x-show="deployments.length === 0" class="text-center py-12 text-slate-400">
                        <i class="fas fa-inbox text-5xl mb-4 opacity-20"></i>
                        <p>No deployments yet</p>
                    </div>
                </div>
            </div>
            
            <!-- Analytics Page -->
            <div x-show="currentPage === 'analytics'" x-transition>
                <h1 class="text-3xl font-bold mb-8">Analytics Dashboard</h1>
                
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                    <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                        <div class="text-sm text-slate-400 mb-2">Total Credits Spent</div>
                        <div class="text-3xl font-bold text-red-400" x-text="analytics.stats.total_credits_spent || 0"></div>
                    </div>
                    <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                        <div class="text-sm text-slate-400 mb-2">Total Credits Earned</div>
                        <div class="text-3xl font-bold text-green-400" x-text="analytics.stats.total_credits_earned || 0"></div>
                    </div>
                    <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                        <div class="text-sm text-slate-400 mb-2">Total Deployments</div>
                        <div class="text-3xl font-bold text-blue-400" x-text="analytics.stats.total_deploys || 0"></div>
                    </div>
                </div>
                
                <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                    <h2 class="text-xl font-bold mb-4">Recent Activity</h2>
                    <div class="space-y-3">
                        <template x-for="event in analytics.events.slice(-10).reverse()" :key="event.timestamp">
                            <div class="bg-slate-800/50 rounded-lg p-4 flex items-center justify-between">
                                <div>
                                    <div class="font-semibold" x-text="event.type.replace(/_/g, ' ').toUpperCase()"></div>
                                    <div class="text-sm text-slate-400" x-text="new Date(event.timestamp).toLocaleString()"></div>
                                </div>
                                <i class="fas fa-circle text-blue-400 text-xs"></i>
                            </div>
                        </template>
                    </div>
                </div>
            </div>
            
            <!-- API Keys Page -->
            <div x-show="currentPage === 'api-keys'" x-transition>
                <h1 class="text-3xl font-bold mb-8">API Keys</h1>
                
                <div class="bg-slate-900 rounded-xl p-6 border border-slate-800 mb-6">
                    <h2 class="text-xl font-bold mb-4">Generate New API Key</h2>
                    <p class="text-slate-400 mb-4">API keys allow programmatic access to EliteHost services</p>
                    <button @click="generateApiKey()" class="bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-lg transition">
                        <i class="fas fa-plus mr-2"></i>Generate API Key
                    </button>
                </div>
                
                <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                    <h2 class="text-xl font-bold mb-4">Your API Keys</h2>
                    <div class="space-y-3" x-show="apiKeys.length > 0">
                        <template x-for="key in apiKeys" :key="key">
                            <div class="bg-slate-800/50 rounded-lg p-4 flex items-center justify-between">
                                <div class="font-mono text-sm" x-text="key"></div>
                                <button @click="copyToClipboard(key)" class="text-blue-400 hover:text-blue-300">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </template>
                    </div>
                    <div x-show="apiKeys.length === 0" class="text-center py-12 text-slate-400">
                        <i class="fas fa-key text-5xl mb-4 opacity-20"></i>
                        <p>No API keys yet</p>
                    </div>
                </div>
            </div>
            
            <!-- Referrals Page -->
            <div x-show="currentPage === 'referrals'" x-transition>
                <h1 class="text-3xl font-bold mb-8">Referral Program</h1>
                
                <div class="bg-gradient-to-r from-blue-600 to-cyan-600 rounded-xl p-8 mb-6 text-white">
                    <h2 class="text-2xl font-bold mb-4">Your Referral Code</h2>
                    <div class="bg-white/20 rounded-lg p-4 mb-4">
                        <div class="flex items-center justify-between">
                            <div class="font-mono text-2xl">{{ referral_code }}</div>
                            <button @click="copyToClipboard('{{ referral_code }}')" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-lg transition">
                                <i class="fas fa-copy mr-2"></i>Copy
                            </button>
                        </div>
                    </div>
                    <p class="text-blue-100">Share this code and earn 1.0 credits for each referral!</p>
                </div>
                
                <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                    <h2 class="text-xl font-bold mb-4">How It Works</h2>
                    <div class="space-y-4">
                        <div class="flex items-start gap-4">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                                <span class="text-blue-400 font-bold">1</span>
                            </div>
                            <div>
                                <h3 class="font-semibold mb-1">Share Your Code</h3>
                                <p class="text-sm text-slate-400">Give your referral code to friends</p>
                            </div>
                        </div>
                        <div class="flex items-start gap-4">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                                <span class="text-blue-400 font-bold">2</span>
                            </div>
                            <div>
                                <h3 class="font-semibold mb-1">They Sign Up</h3>
                                <p class="text-sm text-slate-400">New user registers with your code</p>
                            </div>
                        </div>
                        <div class="flex items-start gap-4">
                            <div class="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                                <span class="text-green-400 font-bold">3</span>
                            </div>
                            <div>
                                <h3 class="font-semibold mb-1">Earn Rewards</h3>
                                <p class="text-sm text-slate-400">You get 1.0 credits, they get 0.5 credits!</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Rest of pages follow same pattern as v12... -->
            
        </div>
    </div>
    
    <script>
        function dashboardApp() {
            return {
                sidebarOpen: false,
                currentPage: 'overview',
                modal: null,
                detailsTab: 'info',
                credits: {{ credits }},
                deployments: [],
                stats: {
                    total: 0,
                    running: 0
                },
                analytics: {{ analytics|tojson }},
                apiKeys: [],
                selectedDeploy: null,
                deployFiles: [],
                consoleLogs: '',
                githubForm: {
                    url: '',
                    branch: 'main',
                    buildCmd: '',
                    startCmd: ''
                },
                newEnv: {
                    key: '',
                    value: ''
                },
                customAmount: '',
                paymentData: {
                    id: '',
                    package: '',
                    credits: 0,
                    price: 0,
                    screenshot: null,
                    transactionId: ''
                },
                timeRemaining: 600,
                timerInterval: null,
                
                init() {
                    this.loadDeployments();
                    this.loadApiKeys();
                    setInterval(() => this.loadDeployments(), 10000);
                    setInterval(() => this.updateCredits(), 15000);
                },
                
                async loadDeployments() {
                    const res = await fetch('/api/deployments');
                    const data = await res.json();
                    if (data.success) {
                        this.deployments = data.deployments;
                        this.stats.total = data.deployments.length;
                        this.stats.running = data.deployments.filter(d => d.status === 'running').length;
                    }
                },
                
                async updateCredits() {
                    const res = await fetch('/api/credits');
                    const data = await res.json();
                    if (data.success) {
                        this.credits = data.credits === Infinity ? '∞' : data.credits.toFixed(1);
                    }
                },
                
                async loadApiKeys() {
                    // Implementation for loading user API keys
                },
                
                async generateApiKey() {
                    const res = await fetch('/api/user/api-key', {
                        method: 'POST'
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.apiKeys.push(data.api_key);
                        this.showNotification('✅ API Key generated!', 'success');
                    } else {
                        this.showNotification('❌ ' + data.error, 'error');
                    }
                },
                
                copyToClipboard(text) {
                    navigator.clipboard.writeText(text);
                    this.showNotification('✅ Copied to clipboard!', 'success');
                },
                
                logout() {
                    if (confirm('Logout from EliteHost?')) {
                        window.location.href = '/logout';
                    }
                },
                
                showNotification(message, type) {
                    alert(message);
                },
                
                formatBytes(bytes) {
                    if (bytes === 0) return '0 B';
                    const k = 1024;
                    const sizes = ['B', 'KB', 'MB', 'GB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
                },
                
                formatDate(date) {
                    return new Date(date).toLocaleString();
                }
            }
        }
    </script>
    <style>
        [x-cloak] { display: none !important; }
    </style>
</body>
</html>
"""
