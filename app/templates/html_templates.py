LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost — {{ title }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Plus+Jakarta+Sans:wght@500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root { --gold: #d4af37; --gold-dark: #b8860b; --black: #0a0a0a; --charcoal: #1a1a1a; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--black);
            background-image: radial-gradient(circle at 0% 0%, rgba(212, 175, 55, 0.05) 0%, transparent 50%),
                              radial-gradient(circle at 100% 100%, rgba(212, 175, 55, 0.02) 0%, transparent 50%);
        }
        h1, h2, h3, h4 { font-family: 'Plus Jakarta Sans', sans-serif; }
        .glass { background: rgba(26, 26, 26, 0.8); backdrop-filter: blur(20px); border: 1px solid rgba(212, 175, 55, 0.1); }
        .btn-luxury {
            background: linear-gradient(135deg, var(--gold) 0%, var(--gold-dark) 100%);
            color: var(--black);
            box-shadow: 0 4px 15px rgba(212, 175, 55, 0.2);
            transition: all 0.3s ease;
        }
        .btn-luxury:hover { transform: translateY(-1px); box-shadow: 0 8px 25px rgba(212, 175, 55, 0.3); }
        .fade-in { animation: fadeIn 0.8s cubic-bezier(0.23, 1, 0.32, 1); }
        @keyframes fadeIn { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }
        input:focus { border-color: var(--gold) !important; box-shadow: 0 0 0 2px rgba(212, 175, 55, 0.1) !important; }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-6">
    <div class="max-w-md w-full fade-in relative z-10">
        <div class="glass rounded-3xl shadow-2xl p-10">
            <div class="text-center mb-10">
                <div class="inline-flex items-center justify-center w-16 h-16 border border-gold/30 rotate-45 mb-8">
                    <i class="fas fa-crown text-gold -rotate-45 text-xl"></i>
                </div>
                <h1 class="text-3xl font-bold tracking-[0.2em] uppercase text-white mb-2">EliteHost</h1>
                <p class="text-gray-500 text-xs uppercase tracking-[0.3em] font-medium">{{ subtitle }}</p>
            </div>

            {% if error %}
            <div class="bg-red-500/5 border border-red-500/20 rounded-xl p-4 mb-6 text-red-400 text-xs tracking-wide fade-in flex items-center gap-3">
                <i class="fas fa-exclamation-circle"></i>{{ error }}
            </div>
            {% endif %}
            {% if success %}
            <div class="bg-green-500/5 border border-green-500/20 rounded-xl p-4 mb-6 text-green-400 text-xs tracking-wide fade-in flex items-center gap-3">
                <i class="fas fa-check-circle"></i>{{ success }}
            </div>
            {% endif %}

            <form method="POST" action="{{ action }}" class="space-y-6" id="authForm">
                <div>
                    <label class="block text-[10px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-3">
                        Email Address
                    </label>
                    <input type="email" name="email" required autocomplete="email"
                        class="w-full px-5 py-4 bg-black/40 border border-white/5 rounded-xl text-white placeholder-gray-600 focus:outline-none transition-all text-sm"
                        placeholder="client@elitehost.com">
                </div>
                <div>
                    <label class="block text-[10px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-3">
                        Security Phrase
                    </label>
                    <div class="relative">
                        <input type="password" name="password" id="passwordField" required
                            class="w-full px-5 py-4 bg-black/40 border border-white/5 rounded-xl text-white placeholder-gray-600 focus:outline-none transition-all pr-14 text-sm"
                            placeholder="••••••••">
                        <button type="button" onclick="togglePwd()" class="absolute right-4 top-4 text-gray-600 hover:text-gold transition-colors">
                            <i class="fas fa-eye" id="eyeIcon"></i>
                        </button>
                    </div>
                </div>
                <button type="submit" id="submitBtn"
                    class="w-full btn-luxury text-[11px] font-bold uppercase tracking-[0.2em] py-5 rounded-xl mt-4">
                    <span id="btnText"><i class="fas fa-{{ icon }} mr-3"></i>{{ button_text }}</span>
                </button>
            </form>

            <p class="text-center mt-10 text-xs text-gray-500 tracking-wide font-light">
                {{ toggle_text }} <a href="{{ toggle_link }}" class="text-gold hover:text-gold-dark font-bold ml-1 transition-colors">{{ toggle_action }}</a>
            </p>

            <div class="mt-10 pt-8 border-t border-white/5 flex flex-col items-center gap-4">
                <div class="flex items-center gap-2 text-[9px] font-bold uppercase tracking-[0.3em] text-gray-600">
                    <i class="fas fa-shield-halved text-gold/40"></i>
                    <span>Encrypted Infrastructure Access</span>
                </div>
                <p class="text-[8px] uppercase tracking-[0.4em] text-gray-700">EliteHost Private Network</p>
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
            txt.innerHTML='<i class="fas fa-spinner fa-spin mr-3"></i>Authorizing...';
        });
    </script>
</body>
</html>"""

LANDING_PAGE_HTML = """<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost — Luxury Cloud Deployment Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Plus+Jakarta+Sans:wght@500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root { --gold: #d4af37; --gold-dark: #b8860b; --black: #0a0a0a; --charcoal: #1a1a1a; }
        body { font-family: 'Inter', sans-serif; background-color: var(--black); color: #e5e5e5; }
        h1, h2, h3, h4, .font-heading { font-family: 'Plus Jakarta Sans', sans-serif; }
        .glass-nav { background: rgba(10, 10, 10, 0.8); backdrop-filter: blur(20px); border-bottom: 1px solid rgba(212, 175, 55, 0.1); }
        .text-gold { color: var(--gold); }
        .bg-gold { background-color: var(--gold); }
        .border-gold { border-color: rgba(212, 175, 55, 0.3); }
        .btn-luxury {
            background: linear-gradient(135deg, var(--gold) 0%, var(--gold-dark) 100%);
            color: var(--black);
            font-weight: 700;
            transition: all 0.4s cubic-bezier(0.23, 1, 0.32, 1);
            box-shadow: 0 4px 15px rgba(212, 175, 55, 0.2);
        }
        .btn-luxury:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(212, 175, 55, 0.4);
            filter: brightness(1.1);
        }
        .gold-gradient-text {
            background: linear-gradient(to right, #d4af37, #f7e7ce, #b8860b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .luxury-card {
            background: var(--charcoal);
            border: 1px solid rgba(212, 175, 55, 0.1);
            transition: all 0.5s ease;
        }
        .luxury-card:hover {
            border-color: rgba(212, 175, 55, 0.4);
            transform: translateY(-8px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
        }
        .scroll-reveal { opacity: 0; transform: translateY(30px); transition: all 0.8s ease-out; }
        .scroll-reveal.visible { opacity: 1; transform: translateY(0); }
        .cinematic-overlay {
            background: radial-gradient(circle at 50% 50%, rgba(212, 175, 55, 0.05) 0%, transparent 70%);
        }
        .sep-line { height: 1px; background: linear-gradient(to right, transparent, rgba(212, 175, 55, 0.3), transparent); }
    </style>
</head>
<body x-data="{ mobileMenu: false, scrolled: false }" @scroll.window="scrolled = (window.pageYOffset > 20)" class="overflow-x-hidden">

    <!-- Navigation -->
    <nav class="fixed top-0 w-full z-50 transition-all duration-500" :class="scrolled ? 'glass-nav py-4' : 'bg-transparent py-7'">
        <div class="max-w-7xl mx-auto px-8 flex items-center justify-between">
            <div class="flex items-center gap-3 group cursor-pointer">
                <div class="w-10 h-10 border border-gold flex items-center justify-center rotate-45 group-hover:rotate-180 transition-transform duration-700">
                    <i class="fas fa-crown text-gold -rotate-45 group-hover:rotate-180 transition-transform duration-700 text-sm"></i>
                </div>
                <span class="text-2xl font-bold tracking-[0.2em] uppercase text-white">EliteHost</span>
            </div>

            <!-- Desktop Menu -->
            <div class="hidden lg:flex items-center gap-10 text-[11px] font-bold uppercase tracking-[0.2em] text-gray-400">
                <a href="#features" class="hover:text-gold transition-colors">Experience</a>
                <a href="#process" class="hover:text-gold transition-colors">Philosophy</a>
                <a href="#pricing" class="hover:text-gold transition-colors">Investment</a>
                <a href="#faq" class="hover:text-gold transition-colors">Concierge</a>
            </div>

            <div class="hidden lg:flex items-center gap-8">
                <a href="/login" class="text-[11px] font-bold uppercase tracking-[0.2em] text-white hover:text-gold transition-colors">Client Login</a>
                <a href="/register" class="btn-luxury px-8 py-3 text-[11px] uppercase tracking-[0.2em]">Begin Journey</a>
            </div>

            <!-- Mobile Toggle -->
            <button class="lg:hidden text-gold" @click="mobileMenu = !mobileMenu">
                <i class="fas" :class="mobileMenu ? 'fa-times' : 'fa-bars-staggered'"></i>
            </button>
        </div>

        <!-- Mobile Menu -->
        <div x-show="mobileMenu" x-cloak x-transition class="lg:hidden absolute top-0 left-0 w-full h-screen bg-black flex flex-col items-center justify-center space-y-8 z-[60]">
            <button class="absolute top-8 right-8 text-gold text-2xl" @click="mobileMenu = false"><i class="fas fa-times"></i></button>
            <a href="#features" @click="mobileMenu = false" class="text-2xl font-light tracking-[0.3em] uppercase">Experience</a>
            <a href="#process" @click="mobileMenu = false" class="text-2xl font-light tracking-[0.3em] uppercase">Philosophy</a>
            <a href="#pricing" @click="mobileMenu = false" class="text-2xl font-light tracking-[0.3em] uppercase">Investment</a>
            <div class="pt-8 flex flex-col items-center gap-6 w-full px-12">
                <a href="/login" class="text-[11px] font-bold uppercase tracking-[0.2em] text-white">Client Login</a>
                <a href="/register" class="btn-luxury w-full text-center py-4 text-[11px] uppercase tracking-[0.2em]">Begin Journey</a>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <header class="relative min-h-screen flex items-center justify-center pt-20 overflow-hidden">
        <div class="absolute inset-0 cinematic-overlay"></div>
        <div class="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full opacity-20">
            <div class="absolute top-1/4 left-1/4 w-[500px] h-[500px] bg-gold/10 rounded-full blur-[120px]"></div>
            <div class="absolute bottom-1/4 right-1/4 w-[500px] h-[500px] bg-gold/5 rounded-full blur-[120px]"></div>
        </div>

        <div class="max-w-7xl mx-auto px-8 relative z-10 text-center">
            <div class="inline-block mb-6 scroll-reveal">
                <span class="text-[10px] font-bold uppercase tracking-[0.5em] text-gold border-b border-gold/30 pb-2">The Standard of Excellence</span>
            </div>
            <h1 class="text-6xl md:text-8xl font-heading font-semibold mb-8 tracking-tight leading-tight scroll-reveal" style="transition-delay: 200ms">
                Deploy with <br><span class="gold-gradient-text italic">Unrivaled Distinction.</span>
            </h1>
            <p class="text-lg md:text-xl text-gray-400 mb-12 max-w-2xl mx-auto font-light leading-relaxed tracking-wide scroll-reveal" style="transition-delay: 400ms">
                EliteHost redefines cloud infrastructure for the discerning developer. An ecosystem where performance meets prestige, and complex architecture becomes effortless.
            </p>
            <div class="flex flex-col sm:flex-row items-center justify-center gap-8 scroll-reveal" style="transition-delay: 600ms">
                <a href="/register" class="btn-luxury px-12 py-5 text-xs uppercase tracking-[0.2em]">Request Access</a>
                <a href="#features" class="group flex items-center gap-3 text-[11px] font-bold uppercase tracking-[0.2em] text-white hover:text-gold transition-colors">
                    Explore Experience <i class="fas fa-chevron-right text-[10px] group-hover:translate-x-2 transition-transform"></i>
                </a>
            </div>
        </div>

        <!-- Floating Decorative Elements -->
        <div class="absolute bottom-12 left-1/2 -translate-x-1/2 flex flex-col items-center gap-4 scroll-reveal" style="transition-delay: 800ms">
            <span class="text-[9px] uppercase tracking-[0.4em] text-gray-500">Scroll</span>
            <div class="w-[1px] h-12 bg-gradient-to-b from-gold to-transparent"></div>
        </div>
    </header>

    <!-- Stats Section (Asymmetric) -->
    <section class="py-32 bg-[#080808] border-y border-white/5">
        <div class="max-w-7xl mx-auto px-8">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-16">
                <div class="scroll-reveal">
                    <div class="text-4xl font-heading font-light text-white mb-2">99.99<span class="text-gold">%</span></div>
                    <div class="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-500">Uptime Guarantee</div>
                </div>
                <div class="scroll-reveal" style="transition-delay: 100ms">
                    <div class="text-4xl font-heading font-light text-white mb-2">200<span class="text-gold">ms</span></div>
                    <div class="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-500">Global Response</div>
                </div>
                <div class="scroll-reveal" style="transition-delay: 200ms">
                    <div class="text-4xl font-heading font-light text-white mb-2">50<span class="text-gold">M+</span></div>
                    <div class="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-500">Processed Requests</div>
                </div>
                <div class="scroll-reveal" style="transition-delay: 300ms">
                    <div class="text-4xl font-heading font-light text-white mb-2">24<span class="text-gold">/7</span></div>
                    <div class="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-500">Private Concierge</div>
                </div>
            </div>
        </div>
    </section>

    <!-- Features Grid (Premium) -->
    <section id="features" class="py-32 relative">
        <div class="max-w-7xl mx-auto px-8">
            <div class="flex flex-col lg:flex-row justify-between items-end mb-24 gap-8">
                <div class="max-w-2xl scroll-reveal">
                    <span class="text-gold text-[11px] font-bold uppercase tracking-[0.3em] mb-4 block">The Experience</span>
                    <h2 class="text-4xl md:text-5xl font-heading font-semibold text-white leading-tight">Mastery in every <br>technical detail.</h2>
                </div>
                <p class="text-gray-500 max-w-sm mb-2 scroll-reveal" style="transition-delay: 200ms">
                    We've distilled the complexity of cloud hosting into a seamless, high-performance interface.
                </p>
            </div>

            <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-1px bg-white/5 border border-white/5">
                <!-- Feature 1 -->
                <div class="bg-black p-12 hover:bg-charcoal transition-colors group scroll-reveal">
                    <div class="text-gold text-2xl mb-8 group-hover:scale-110 transition-transform duration-500"><i class="fas fa-bolt-lightning"></i></div>
                    <h3 class="text-xl font-heading font-semibold text-white mb-4">Instantaneous Flow</h3>
                    <p class="text-gray-500 text-sm leading-relaxed font-light">From commit to production in seconds. Our proprietary build engine ensures zero friction in your deployment pipeline.</p>
                </div>
                <!-- Feature 2 -->
                <div class="bg-black p-12 hover:bg-charcoal transition-colors group scroll-reveal" style="transition-delay: 100ms">
                    <div class="text-gold text-2xl mb-8 group-hover:scale-110 transition-transform duration-500"><i class="fas fa-brain"></i></div>
                    <h3 class="text-xl font-heading font-semibold text-white mb-4">Cognitive Coder</h3>
                    <p class="text-gray-500 text-sm leading-relaxed font-light">Leverage advanced neural networks to generate, optimize, and scale your application code through natural language.</p>
                </div>
                <!-- Feature 3 -->
                <div class="bg-black p-12 hover:bg-charcoal transition-colors group scroll-reveal" style="transition-delay: 200ms">
                    <div class="text-gold text-2xl mb-8 group-hover:scale-110 transition-transform duration-500"><i class="fas fa-shield-halved"></i></div>
                    <h3 class="text-xl font-heading font-semibold text-white mb-4">Fortified Isolation</h3>
                    <p class="text-gray-500 text-sm leading-relaxed font-light">Every deployment exists in a cryptographically secured, isolated container with multi-layered biometric authentication.</p>
                </div>
                <!-- Feature 4 -->
                <div class="bg-black p-12 hover:bg-charcoal transition-colors group scroll-reveal" style="transition-delay: 300ms">
                    <div class="text-gold text-2xl mb-8 group-hover:scale-110 transition-transform duration-500"><i class="fas fa-chart-pie"></i></div>
                    <h3 class="text-xl font-heading font-semibold text-white mb-4">Precision Metrics</h3>
                    <p class="text-gray-500 text-sm leading-relaxed font-light">Real-time telemetry providing granular insights into your application's performance and resource utilization.</p>
                </div>
                <!-- Feature 5 -->
                <div class="bg-black p-12 hover:bg-charcoal transition-colors group scroll-reveal" style="transition-delay: 400ms">
                    <div class="text-gold text-2xl mb-8 group-hover:scale-110 transition-transform duration-500"><i class="fab fa-github"></i></div>
                    <h3 class="text-xl font-heading font-semibold text-white mb-4">Seamless Integration</h3>
                    <p class="text-gray-500 text-sm leading-relaxed font-light">Deep synchronization with your existing workflow, from GitHub repositories to complex CI/CD environments.</p>
                </div>
                <!-- Feature 6 -->
                <div class="bg-black p-12 hover:bg-charcoal transition-colors group scroll-reveal" style="transition-delay: 500ms">
                    <div class="text-gold text-2xl mb-8 group-hover:scale-110 transition-transform duration-500"><i class="fas fa-leaf"></i></div>
                    <h3 class="text-xl font-heading font-semibold text-white mb-4">Infinite Scalability</h3>
                    <p class="text-gray-500 text-sm leading-relaxed font-light">Our elastic cluster automatically expands to meet your application's demand, ensuring consistent performance at any scale.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Philosophy Section (Timeline) -->
    <section id="process" class="py-32 bg-[#080808]">
        <div class="max-w-7xl mx-auto px-8">
            <div class="text-center mb-24 scroll-reveal">
                <span class="text-gold text-[11px] font-bold uppercase tracking-[0.3em] mb-4 block">The Philosophy</span>
                <h2 class="text-4xl md:text-5xl font-heading font-semibold text-white">Three stages to prestige.</h2>
            </div>

            <div class="relative space-y-24">
                <div class="absolute left-1/2 top-0 bottom-0 w-[1px] bg-gold/10 hidden md:block"></div>

                <!-- Step 1 -->
                <div class="flex flex-col md:flex-row items-center gap-12 md:gap-24 relative z-10 scroll-reveal">
                    <div class="flex-1 md:text-right">
                        <div class="text-gold text-xs font-bold uppercase tracking-[0.3em] mb-4">Stage One</div>
                        <h3 class="text-2xl font-heading font-semibold text-white mb-4">Genesis of Code</h3>
                        <p class="text-gray-500 text-sm leading-relaxed font-light max-w-md md:ml-auto">Connect your source through our secure gateway. Whether raw code or repository, the architecture is instantly understood.</p>
                    </div>
                    <div class="w-16 h-16 bg-black border border-gold rounded-full flex items-center justify-center text-gold font-heading text-xl shadow-[0_0_20px_rgba(212,175,55,0.2)]">01</div>
                    <div class="flex-1 hidden md:block"></div>
                </div>

                <!-- Step 2 -->
                <div class="flex flex-col md:flex-row items-center gap-12 md:gap-24 relative z-10 scroll-reveal" style="transition-delay: 200ms">
                    <div class="flex-1 hidden md:block"></div>
                    <div class="w-16 h-16 bg-black border border-gold rounded-full flex items-center justify-center text-gold font-heading text-xl shadow-[0_0_20px_rgba(212,175,55,0.2)]">02</div>
                    <div class="flex-1">
                        <div class="text-gold text-xs font-bold uppercase tracking-[0.3em] mb-4">Stage Two</div>
                        <h3 class="text-2xl font-heading font-semibold text-white mb-4">Alchemical Build</h3>
                        <p class="text-gray-500 text-sm leading-relaxed font-light max-w-md">Our engine intelligently assembles dependencies and optimizes your environment for peak performance and security.</p>
                    </div>
                </div>

                <!-- Step 3 -->
                <div class="flex flex-col md:flex-row items-center gap-12 md:gap-24 relative z-10 scroll-reveal" style="transition-delay: 400ms">
                    <div class="flex-1 md:text-right">
                        <div class="text-gold text-xs font-bold uppercase tracking-[0.3em] mb-4">Stage Three</div>
                        <h3 class="text-2xl font-heading font-semibold text-white mb-4">Eternal Presence</h3>
                        <p class="text-gray-500 text-sm leading-relaxed font-light max-w-md md:ml-auto">Your application is broadcast to our global high-availability network, protected by the industry's most robust security protocols.</p>
                    </div>
                    <div class="w-16 h-16 bg-black border border-gold rounded-full flex items-center justify-center text-gold font-heading text-xl shadow-[0_0_20px_rgba(212,175,55,0.2)]">03</div>
                    <div class="flex-1 hidden md:block"></div>
                </div>
            </div>
        </div>
    </section>

    <!-- Testimonials (Cinematic) -->
    <section class="py-32 overflow-hidden">
        <div class="max-w-7xl mx-auto px-8 relative">
            <div class="text-8xl absolute top-0 left-0 text-gold/5 font-heading select-none font-bold">Voices</div>
            <div class="grid lg:grid-cols-3 gap-12 pt-16">
                <div class="luxury-card p-10 scroll-reveal">
                    <div class="flex gap-1 text-gold mb-6 text-[10px]">
                        <i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i>
                    </div>
                    <p class="text-white text-lg font-light leading-relaxed mb-10 italic">"The level of sophistication in their deployment pipeline is unmatched. It's not just hosting; it's a statement of quality for our brand."</p>
                    <div class="flex items-center gap-4">
                        <div class="w-12 h-12 rounded-full border border-gold/30 p-1">
                            <img src="https://i.pravatar.cc/100?u=1" class="w-full h-full rounded-full grayscale" alt="Client">
                        </div>
                        <div>
                            <div class="text-white font-bold text-sm tracking-widest uppercase">Alexander Vance</div>
                            <div class="text-gold text-[10px] font-bold uppercase tracking-[0.2em]">CTO, LuxDigital</div>
                        </div>
                    </div>
                </div>
                <div class="luxury-card p-10 mt-12 scroll-reveal" style="transition-delay: 200ms">
                    <div class="flex gap-1 text-gold mb-6 text-[10px]">
                        <i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i>
                    </div>
                    <p class="text-white text-lg font-light leading-relaxed mb-10 italic">"The AI Coder changed everything. We went from concept to a production-ready luxury store in a weekend. Extraordinary."</p>
                    <div class="flex items-center gap-4">
                        <div class="w-12 h-12 rounded-full border border-gold/30 p-1">
                            <img src="https://i.pravatar.cc/100?u=2" class="w-full h-full rounded-full grayscale" alt="Client">
                        </div>
                        <div>
                            <div class="text-white font-bold text-sm tracking-widest uppercase">Sofia Rossi</div>
                            <div class="text-gold text-[10px] font-bold uppercase tracking-[0.2em]">Founder, Aura</div>
                        </div>
                    </div>
                </div>
                <div class="luxury-card p-10 scroll-reveal" style="transition-delay: 400ms">
                    <div class="flex gap-1 text-gold mb-6 text-[10px]">
                        <i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i>
                    </div>
                    <p class="text-white text-lg font-light leading-relaxed mb-10 italic">"Security is paramount for us. EliteHost's biometric-locked containers give us the peace of mind that traditional hosts simply cannot."</p>
                    <div class="flex items-center gap-4">
                        <div class="w-12 h-12 rounded-full border border-gold/30 p-1">
                            <img src="https://i.pravatar.cc/100?u=3" class="w-full h-full rounded-full grayscale" alt="Client">
                        </div>
                        <div>
                            <div class="text-white font-bold text-sm tracking-widest uppercase">Julian Thorne</div>
                            <div class="text-gold text-[10px] font-bold uppercase tracking-[0.2em]">Lead Architect, Prism</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Investment Section (Pricing) -->
    <section id="pricing" class="py-32 bg-[#080808]">
        <div class="max-w-7xl mx-auto px-8">
            <div class="text-center mb-24 scroll-reveal">
                <span class="text-gold text-[11px] font-bold uppercase tracking-[0.3em] mb-4 block">The Investment</span>
                <h2 class="text-4xl md:text-5xl font-heading font-semibold text-white">Curated credit Tiers.</h2>
            </div>

            <div class="grid md:grid-cols-3 gap-8">
                <!-- Tier 1 -->
                <div class="luxury-card p-12 flex flex-col scroll-reveal">
                    <h3 class="text-[10px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-8">Essential Entry</h3>
                    <div class="flex items-baseline gap-2 mb-10">
                        <span class="text-5xl font-heading font-light text-white">₹50</span>
                        <span class="text-gray-500 text-xs">/ 10 cr</span>
                    </div>
                    <div class="sep-line mb-10"></div>
                    <ul class="space-y-6 flex-1 mb-12">
                        <li class="flex items-center gap-4 text-xs tracking-wider text-gray-400">
                            <i class="fas fa-check text-gold text-[10px]"></i> 20 Refined Deployments
                        </li>
                        <li class="flex items-center gap-4 text-xs tracking-wider text-gray-400">
                            <i class="fas fa-check text-gold text-[10px]"></i> GitHub Cluster Sync
                        </li>
                        <li class="flex items-center gap-4 text-xs tracking-wider text-gray-400">
                            <i class="fas fa-check text-gold text-[10px]"></i> Digital Concierge Support
                        </li>
                    </ul>
                    <a href="/register" class="border border-gold/30 text-gold py-4 text-center text-[10px] uppercase tracking-[0.3em] font-bold hover:bg-gold hover:text-black transition-all">Select Tier</a>
                </div>

                <!-- Tier 2 (Highlighted) -->
                <div class="luxury-card p-12 flex flex-col border-gold relative transform scale-105 z-10 scroll-reveal" style="transition-delay: 200ms">
                    <div class="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-gold text-black text-[9px] font-bold uppercase tracking-[0.3em] px-6 py-2">Most Distinguished</div>
                    <h3 class="text-[10px] font-bold uppercase tracking-[0.3em] text-gold mb-8">Professional Suite</h3>
                    <div class="flex items-baseline gap-2 mb-1">
                        <span class="text-5xl font-heading font-light text-white">₹399</span>
                        <span class="text-gold text-xs">/ 99 cr</span>
                    </div>
                    <div class="text-[10px] text-gold font-bold italic tracking-wider mb-9 uppercase">Exceptional Value</div>
                    <div class="sep-line mb-10"></div>
                    <ul class="space-y-6 flex-1 mb-12">
                        <li class="flex items-center gap-4 text-xs tracking-wider text-white">
                            <i class="fas fa-check text-gold text-[10px]"></i> 198 Prime Deployments
                        </li>
                        <li class="flex items-center gap-4 text-xs tracking-wider text-white">
                            <i class="fas fa-check text-gold text-[10px]"></i> Universal API Access
                        </li>
                        <li class="flex items-center gap-4 text-xs tracking-wider text-white">
                            <i class="fas fa-check text-gold text-[10px]"></i> Priority Private Support
                        </li>
                        <li class="flex items-center gap-4 text-xs tracking-wider text-white">
                            <i class="fas fa-check text-gold text-[10px]"></i> Advanced Beta Privilege
                        </li>
                    </ul>
                    <a href="/register" class="btn-luxury py-5 text-center text-[10px] uppercase tracking-[0.3em]">Acquire Now</a>
                </div>

                <!-- Tier 3 -->
                <div class="luxury-card p-12 flex flex-col scroll-reveal" style="transition-delay: 400ms">
                    <h3 class="text-[10px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-8">Bespoke Enterprise</h3>
                    <div class="flex items-baseline gap-2 mb-10">
                        <span class="text-4xl font-heading font-light text-white">Tailored</span>
                    </div>
                    <div class="sep-line mb-10"></div>
                    <p class="text-gray-500 text-xs leading-relaxed font-light mb-10">For institutional-scale requirements and custom architectural needs.</p>
                    <ul class="space-y-6 flex-1 mb-12">
                        <li class="flex items-center gap-4 text-xs tracking-wider text-gray-400">
                            <i class="fas fa-check text-gold text-[10px]"></i> Unlimited Potential
                        </li>
                        <li class="flex items-center gap-4 text-xs tracking-wider text-gray-400">
                            <i class="fas fa-check text-gold text-[10px]"></i> Dedicated Account Partner
                        </li>
                    </ul>
                    <a href="https://t.me/zolvid" class="border border-gold/30 text-gold py-4 text-center text-[10px] uppercase tracking-[0.3em] font-bold hover:bg-gold hover:text-black transition-all">Initiate Dialogue</a>
                </div>
            </div>
        </div>
    </section>

    <!-- FAQ (Accordion) -->
    <section id="faq" class="py-32">
        <div class="max-w-3xl mx-auto px-8">
            <div class="text-center mb-24 scroll-reveal">
                <span class="text-gold text-[11px] font-bold uppercase tracking-[0.3em] mb-4 block">The Concierge</span>
                <h2 class="text-4xl font-heading font-semibold text-white">Clarifications.</h2>
            </div>

            <div class="space-y-4" x-data="{ active: 0 }">
                <template x-for="(q, index) in [
                    {q: 'What environments are supported?', a: 'EliteHost currently provides elite-tier support for Python (Flask, Django, FastAPI) and Node.js frameworks. Our infrastructure is constantly expanding to accommodate more sophisticated runtimes.'},
                    {q: 'The Philosophy behind Credits?', a: 'Credits represent our currency of value. They allow for a precise, investment-based approach to hosting, where you pay strictly for the value and performance your applications consume.'},
                    {q: 'Data Integrity & Sovereignty?', a: 'We employ military-grade encryption and decentralized storage snapshots. Your data resides within private, biometric-locked containerized environments, ensuring absolute sovereignty.'},
                    {q: 'Custom Domain Integration?', a: 'Every deployment is granted a high-prestige dedicated port on our global cluster. Direct custom domain aliasing is part of our upcoming prestige update.'}
                ]">
                    <div class="luxury-card overflow-hidden" :class="active === index ? 'border-gold/50' : 'border-white/5'">
                        <button @click="active = index" class="w-full flex items-center justify-between p-8 text-left group">
                            <span class="text-xs font-bold uppercase tracking-[0.2em] transition-colors" :class="active === index ? 'text-gold' : 'text-white group-hover:text-gold'" x-text="q.q"></span>
                            <i class="fas fa-plus text-[10px] text-gold transition-transform duration-500" :class="active === index ? 'rotate-45' : ''"></i>
                        </button>
                        <div x-show="active === index" x-collapse>
                            <div class="px-8 pb-8 text-gray-500 text-sm font-light leading-relaxed tracking-wide" x-text="q.a"></div>
                        </div>
                    </div>
                </template>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="bg-black border-t border-white/5 pt-32 pb-16">
        <div class="max-w-7xl mx-auto px-8">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-20 mb-32">
                <div class="col-span-1 md:col-span-2">
                    <div class="flex items-center gap-3 mb-10 group cursor-pointer">
                        <div class="w-8 h-8 border border-gold flex items-center justify-center rotate-45 group-hover:rotate-180 transition-transform duration-700">
                            <i class="fas fa-crown text-gold -rotate-45 group-hover:rotate-180 transition-transform duration-700 text-[10px]"></i>
                        </div>
                        <span class="text-xl font-bold tracking-[0.2em] uppercase text-white">EliteHost</span>
                    </div>
                    <p class="text-gray-500 text-sm font-light leading-relaxed tracking-wide max-w-sm mb-10">
                        Crafting the future of cloud infrastructure with a commitment to performance, elegance, and absolute technical mastery.
                    </p>
                    <div class="flex gap-8">
                        <a href="#" class="text-gray-600 hover:text-gold transition-colors"><i class="fab fa-twitter"></i></a>
                        <a href="https://t.me/zolvid" class="text-gray-600 hover:text-gold transition-colors"><i class="fab fa-telegram"></i></a>
                        <a href="#" class="text-gray-600 hover:text-gold transition-colors"><i class="fab fa-instagram"></i></a>
                    </div>
                </div>
                <div>
                    <h5 class="text-white text-[10px] font-bold uppercase tracking-[0.3em] mb-8">Ecosystem</h5>
                    <ul class="space-y-4 text-[10px] font-bold uppercase tracking-[0.2em] text-gray-600">
                        <li><a href="#features" class="hover:text-gold transition-colors">Experience</a></li>
                        <li><a href="#pricing" class="hover:text-gold transition-colors">Investment</a></li>
                        <li><a href="/login" class="hover:text-gold transition-colors">Client Login</a></li>
                        <li><a href="/register" class="hover:text-gold transition-colors">Create Portfolio</a></li>
                    </ul>
                </div>
                <div>
                    <h5 class="text-white text-[10px] font-bold uppercase tracking-[0.3em] mb-8">Legal & Support</h5>
                    <ul class="space-y-4 text-[10px] font-bold uppercase tracking-[0.2em] text-gray-600">
                        <li><a href="https://t.me/zolvid" class="hover:text-gold transition-colors">Private Support</a></li>
                        <li><a href="#" class="hover:text-gold transition-colors">Privacy Policy</a></li>
                        <li><a href="#" class="hover:text-gold transition-colors">Terms of Service</a></li>
                        <li><a href="#" class="hover:text-gold transition-colors">API Dossier</a></li>
                    </ul>
                </div>
            </div>
            <div class="flex flex-col md:flex-row justify-between items-center gap-8 pt-16 border-t border-white/5">
                <div class="text-[9px] font-bold uppercase tracking-[0.3em] text-gray-700">
                    © 2024 EliteHost. All Rights Reserved. Engineered for Excellence.
                </div>
                <div class="flex items-center gap-3 text-[9px] font-bold uppercase tracking-[0.4em] text-gold/40">
                    <span class="w-1 h-1 bg-gold rounded-full animate-pulse"></span>
                    System Integrity: Operational
                </div>
            </div>
        </div>
    </footer>

    <script>
        // Simple Intersection Observer for scroll reveals
        document.addEventListener('DOMContentLoaded', () => {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('visible');
                    }
                });
            }, { threshold: 0.1 });

            document.querySelectorAll('.scroll-reveal').forEach(el => observer.observe(el));
        });
    </script>

</body>
</html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost — Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap" rel="stylesheet">
    <style>
        [x-cloak]{display:none!important}
        :root { --gold: #d4af37; --gold-dark: #b8860b; --black: #0a0a0a; --charcoal: #141414; }
        body{
            font-family: 'Inter', sans-serif;
            background: var(--black);
            color: #e5e5e5;
            background-image: radial-gradient(at 0% 0%, rgba(212, 175, 55, 0.03) 0, transparent 50%),
                              radial-gradient(at 100% 0%, rgba(212, 175, 55, 0.02) 0, transparent 50%);
        }
        h1, h2, h3, h4 { font-family: 'Plus Jakarta Sans', sans-serif; }
        .glass{background:rgba(20, 20, 20, 0.7);backdrop-filter:blur(20px);border:1px solid rgba(212, 175, 55, 0.1);box-shadow: 0 20px 50px rgba(0,0,0,0.5);}
        .sidebar{background:var(--black);border-right:1px solid rgba(212, 175, 55, 0.1)}
        .active-nav{background:rgba(212, 175, 55, 0.1); border: 1px solid rgba(212, 175, 55, 0.2); color:var(--gold)}
        .stat-card{background:rgba(20, 20, 20, 0.4);border:1px solid rgba(212, 175, 55, 0.05);transition: all 0.4s cubic-bezier(0.23, 1, 0.32, 1);}
        .stat-card:hover{border-color: rgba(212, 175, 55, 0.3); transform: translateY(-4px); background: rgba(20, 20, 20, 0.6);}
        .btn-luxury{background:linear-gradient(135deg,var(--gold),var(--gold-dark)); color:var(--black); font-weight:700; transition:all .3s ease;}
        .btn-luxury:hover{filter:brightness(1.1); transform:translateY(-1px); box-shadow: 0 10px 20px rgba(212, 175, 55, 0.2);}
        .status-running{background:rgba(34,197,94,0.1);color:#4ade80;border:1px solid rgba(34,197,94,0.2)}
        .status-stopped{background:rgba(239,68,68,0.1);color:#f87171;border:1px solid rgba(239,68,68,0.2)}
        .status-pending{background:rgba(234,179,8,0.1);color:#facc15;border:1px solid rgba(234,179,8,0.2)}
        .status-failed{background:rgba(239,68,68,0.1);color:#f87171;border:1px solid rgba(239,68,68,0.2)}
        .toast{position:fixed;bottom:5rem;right:1.5rem;z-index:9999;max-width:350px;animation:slideIn .4s cubic-bezier(0.23, 1, 0.32, 1)}
        @keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
        .bottom-nav{background:rgba(10,10,10,0.9);backdrop-filter:blur(20px);border-top:1px solid rgba(212, 175, 55, 0.2)}
        .progress-bar{height:4px;border-radius:2px;transition:width 1s ease; background:var(--gold);}
        ::-webkit-scrollbar{width:4px;height:4px}
        ::-webkit-scrollbar-track{background:var(--black)}
        ::-webkit-scrollbar-thumb{background:var(--gold-dark);border-radius:2px}
        .gold-glow { text-shadow: 0 0 10px rgba(212, 175, 55, 0.3); }
    </style>
</head>
<body class="text-white min-h-screen" x-data="dashApp()">

    <!-- Notification Toasts -->
    <div class="toast-container" id="toastContainer"></div>

    <!-- Sidebar -->
    <div class="sidebar fixed inset-y-0 left-0 w-72 z-50 flex flex-col transform transition-transform duration-500 ease-in-out"
         :class="sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'">
        <div class="p-8 flex items-center gap-4 border-b border-white/5">
            <div class="w-12 h-12 border border-gold flex items-center justify-center rotate-45 shadow-[0_0_15px_rgba(212,175,55,0.2)]">
                <i class="fas fa-crown text-gold -rotate-45 text-sm"></i>
            </div>
            <div>
                <span class="text-xl font-bold tracking-[0.2em] uppercase text-white">EliteHost</span>
                <span class="text-[9px] text-gold font-bold uppercase tracking-[0.3em] block mt-0.5">Concierge Access</span>
            </div>
        </div>

        <nav class="flex-1 p-6 space-y-2 overflow-y-auto">
            <template x-for="item in navItems" :key="item.id">
                <button @click="navigate(item.id)"
                    :class="currentPage===item.id ? 'active-nav' : 'text-gray-500 hover:bg-white/5 hover:text-white'"
                    class="w-full flex items-center gap-4 px-5 py-4 rounded-xl cursor-pointer transition-all duration-300 text-left">
                    <i :class="item.icon" class="w-5 text-center text-sm"></i>
                    <span class="text-[11px] font-bold uppercase tracking-[0.2em]" x-text="item.label"></span>
                    <span x-show="item.badge && item.badge > 0"
                        class="ml-auto bg-gold text-black text-[9px] font-black px-2 py-0.5 rounded-full"
                        x-text="item.badge"></span>
                </button>
            </template>
            {% if is_admin %}
            <a href="/admin"
                class="flex items-center gap-4 px-5 py-4 rounded-xl text-gold hover:bg-gold/10 transition-all duration-300">
                <i class="fas fa-fingerprint w-5 text-center text-sm"></i>
                <span class="text-[11px] font-bold uppercase tracking-[0.2em]">Administrative</span>
            </a>
            {% endif %}
        </nav>

        <div class="p-6 border-t border-white/5">
            <div class="bg-gradient-to-br from-gold/10 to-transparent border border-gold/20 rounded-2xl p-5 mb-4">
                <div class="flex items-center justify-between mb-2">
                    <span class="text-[9px] font-bold uppercase tracking-[0.2em] text-gold">Capital Reserve</span>
                    <i class="fas fa-gem text-gold/40 text-[10px]"></i>
                </div>
                <div class="text-3xl font-heading font-light text-white" x-text="credits === Infinity ? '∞' : parseFloat(credits).toFixed(1)"></div>
                <div class="text-[9px] text-gray-500 font-bold uppercase tracking-[0.2em] mt-2">Credits Remaining</div>
            </div>
            <div class="grid grid-cols-1 gap-2">
                <button @click="navigate('buy-credits')"
                    class="btn-luxury w-full py-3.5 rounded-xl text-[10px] uppercase tracking-[0.2em]">
                    Acquire Credits
                </button>
                <button @click="logout()"
                    class="text-gray-600 hover:text-red-400 py-2 text-[9px] font-bold uppercase tracking-[0.3em] transition-colors mt-2">
                    Terminate Session
                </button>
            </div>
        </div>
    </div>

    <!-- Mobile Header -->
    <div class="md:hidden fixed top-0 left-0 right-0 z-40 bg-black/80 backdrop-blur border-b border-white/5 px-6 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 border border-gold flex items-center justify-center rotate-45">
                <i class="fas fa-crown text-gold -rotate-45 text-[10px]"></i>
            </div>
            <span class="text-sm font-bold tracking-[0.2em] uppercase text-white">EliteHost</span>
        </div>
        <div class="flex items-center gap-4">
            <div class="text-[10px] font-bold text-gold tracking-widest" x-text="credits === Infinity ? '∞ cr' : parseFloat(credits).toFixed(1)+' cr'"></div>
            <button @click="sidebarOpen=!sidebarOpen" class="text-gold">
                <i class="fas fa-bars-staggered text-xl"></i>
            </button>
        </div>
    </div>

    <!-- Bottom Navigation (Mobile) -->
    <div class="md:hidden fixed bottom-0 left-0 right-0 z-50 bottom-nav flex justify-around items-center p-3 pb-safe">
        <button @click="navigate('overview')" class="flex flex-col items-center gap-1.5 p-2 transition-colors" :class="currentPage==='overview' ? 'text-gold' : 'text-gray-600'">
            <i class="fas fa-columns text-sm"></i>
            <span class="text-[8px] font-bold uppercase tracking-widest">Main</span>
        </button>
        <button @click="navigate('buy-credits')" class="flex flex-col items-center gap-1.5 p-2 transition-colors" :class="currentPage==='buy-credits' ? 'text-gold' : 'text-gray-600'">
            <i class="fas fa-gem text-sm"></i>
            <span class="text-[8px] font-bold uppercase tracking-widest">Capital</span>
        </button>
        <button @click="navigate('new-deploy')" class="flex flex-col items-center gap-1 p-2 transition">
            <div class="w-14 h-14 bg-gold rounded-full flex items-center justify-center -mt-10 border-4 border-black shadow-[0_10px_25px_rgba(212,175,55,0.3)]">
                <i class="fas fa-wand-magic-sparkles text-black text-lg"></i>
            </div>
            <span class="text-[8px] font-bold uppercase tracking-widest mt-1 text-gold">Genesis</span>
        </button>
        <button @click="navigate('deployments')" class="flex flex-col items-center gap-1.5 p-2 transition-colors" :class="currentPage==='deployments' ? 'text-gold' : 'text-gray-600'">
            <i class="fas fa-rocket text-sm"></i>
            <span class="text-[8px] font-bold uppercase tracking-widest">Deploys</span>
        </button>
        <button @click="window.open('{{ telegram_link }}', '_blank')" class="flex flex-col items-center gap-1.5 p-2 text-gray-600">
            <i class="fas fa-comment-dots text-sm"></i>
            <span class="text-[8px] font-bold uppercase tracking-widest">Help</span>
        </button>
    </div>

    <!-- Overlay -->
    <div x-show="sidebarOpen" @click="sidebarOpen=false"
         class="md:hidden fixed inset-0 bg-black/90 z-40" x-cloak x-transition.opacity></div>

    <!-- Main Content -->
    <main class="md:ml-72 min-h-screen pt-24 md:pt-0 pb-32 md:pb-0">
        <div class="p-8 md:p-12 max-w-7xl mx-auto">

            <!-- OVERVIEW PAGE -->
            <div x-show="currentPage==='overview'" x-transition:enter="transition ease-out duration-500" x-transition:enter-start="opacity-0 translate-y-8" x-transition:enter-end="opacity-100 translate-y-0">
                <div class="flex flex-col md:flex-row md:items-end justify-between mb-12 gap-6">
                    <div>
                        <span class="text-gold text-[10px] font-bold uppercase tracking-[0.4em] mb-3 block">Portfolio Summary</span>
                        <h1 class="text-4xl md:text-5xl font-heading font-semibold text-white tracking-tight">Ecosystem Control</h1>
                    </div>
                    <div class="flex items-center gap-4 bg-white/5 px-6 py-3 rounded-2xl border border-white/5">
                        <div class="w-2 h-2 bg-gold rounded-full animate-pulse shadow-[0_0_10px_rgba(212,175,55,0.5)]"></div>
                        <span class="text-[10px] font-bold uppercase tracking-[0.2em] text-gold">Real-time Telemetry Active</span>
                    </div>
                </div>

                <!-- Stats -->
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
                    <div class="stat-card rounded-3xl p-8">
                        <div class="w-10 h-10 border border-gold/20 flex items-center justify-center mb-6">
                            <i class="fas fa-rocket text-gold text-xs"></i>
                        </div>
                        <div class="text-3xl font-heading font-light text-white mb-1" x-text="stats.total"></div>
                        <div class="text-[9px] font-bold uppercase tracking-[0.2em] text-gray-500">Total Architecture</div>
                    </div>
                    <div class="stat-card rounded-3xl p-8">
                        <div class="w-10 h-10 border border-green-500/20 flex items-center justify-center mb-6">
                            <i class="fas fa-signal text-green-500 text-xs"></i>
                        </div>
                        <div class="text-3xl font-heading font-light text-green-500 mb-1" x-text="stats.running"></div>
                        <div class="text-[9px] font-bold uppercase tracking-[0.2em] text-gray-500">Active Presence</div>
                    </div>
                    <div class="stat-card rounded-3xl p-8 border-gold/20 bg-gold/[0.02]">
                        <div class="w-10 h-10 border border-gold/40 flex items-center justify-center mb-6">
                            <i class="fas fa-gem text-gold text-xs"></i>
                        </div>
                        <div class="text-3xl font-heading font-light text-gold mb-1" x-text="credits === Infinity ? '∞' : parseFloat(credits).toFixed(1)"></div>
                        <div class="text-[9px] font-bold uppercase tracking-[0.2em] text-gold/60">Asset Value</div>
                    </div>
                    <div class="stat-card rounded-3xl p-8">
                        <div class="w-10 h-10 border border-purple-500/20 flex items-center justify-center mb-6">
                            <i class="fas fa-brain text-purple-500 text-xs"></i>
                        </div>
                        <div class="text-3xl font-heading font-light text-purple-500 mb-1">AI</div>
                        <div class="text-[9px] font-bold uppercase tracking-[0.2em] text-gray-500">Neural Engine</div>
                    </div>
                </div>

                <!-- Recent Deployments -->
                <div class="glass rounded-[40px] p-10">
                    <div class="flex items-center justify-between mb-10">
                        <h2 class="text-xl font-heading font-semibold text-white tracking-wide">Recent Deployments</h2>
                        <button @click="navigate('deployments')" class="text-gold text-[10px] font-bold uppercase tracking-[0.3em] hover:tracking-[0.4em] transition-all">View Full Dossier →</button>
                    </div>
                    <div class="space-y-4" x-show="deployments.length > 0">
                        <template x-for="d in deployments.slice(0,5)" :key="d.id">
                            <div class="bg-white/[0.02] border border-white/5 rounded-2xl p-6 flex items-center justify-between hover:border-gold/30 transition-all group">
                                <div class="flex items-center gap-6">
                                    <div class="w-12 h-12 border border-gold/20 flex items-center justify-center group-hover:border-gold group-hover:shadow-[0_0_15px_rgba(212,175,55,0.2)] transition-all">
                                        <i class="fas fa-rocket text-gold text-sm"></i>
                                    </div>
                                    <div>
                                        <div class="font-bold text-sm tracking-widest uppercase text-white group-hover:text-gold transition-colors" x-text="d.name"></div>
                                        <div class="text-[10px] text-gray-500 font-bold tracking-widest mt-1"><span x-text="d.id"></span> · PORT <span x-text="d.port"></span></div>
                                    </div>
                                </div>
                                <span class="px-5 py-2 rounded-full text-[9px] font-black tracking-[0.2em] uppercase transition-all"
                                      :class="'status-'+d.status" x-text="d.status"></span>
                            </div>
                        </template>
                    </div>
                    <div x-show="deployments.length===0" class="text-center py-24">
                        <div class="w-20 h-20 border border-white/5 flex items-center justify-center mx-auto mb-8 rotate-45">
                            <i class="fas fa-satellite-dish text-gray-700 -rotate-45 text-2xl"></i>
                        </div>
                        <p class="text-[11px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-8">No Active Infrastructure</p>
                        <button @click="navigate('new-deploy')" class="btn-luxury px-10 py-4 rounded-xl text-[10px] uppercase tracking-[0.3em]">
                            Initialize First Deploy
                        </button>
                    </div>
                </div>
            </div>

            <!-- DEPLOYMENTS PAGE -->
            <div x-show="currentPage==='deployments'" x-transition:enter="transition ease-out duration-500" x-transition:enter-start="opacity-0 translate-y-8" x-transition:enter-end="opacity-100 translate-y-0">
                <div class="flex items-center justify-between mb-12">
                    <h1 class="text-3xl font-heading font-semibold">Active Infrastructure</h1>
                    <button @click="loadDeployments(true)" class="btn-luxury px-6 py-2.5 rounded-xl text-[10px] uppercase tracking-[0.2em]">
                        <i class="fas fa-sync-alt mr-2"></i>Synchronize
                    </button>
                </div>
                <div class="grid gap-6">
                    <template x-for="d in deployments" :key="d.id">
                        <div class="glass rounded-3xl p-8 hover:border-gold/30 transition-all group">
                            <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-8 mb-8">
                                <div class="flex items-center gap-6">
                                    <div class="w-14 h-14 border border-gold/20 flex items-center justify-center rotate-45 group-hover:border-gold group-hover:shadow-[0_0_15px_rgba(212,175,55,0.2)] transition-all">
                                        <i class="fas fa-rocket text-gold -rotate-45 text-lg"></i>
                                    </div>
                                    <div>
                                        <h3 class="text-lg font-bold uppercase tracking-widest text-white mb-2" x-text="d.name"></h3>
                                        <div class="flex flex-wrap gap-4 text-[10px] text-gray-500 font-bold tracking-widest uppercase">
                                            <span>ID: <span class="text-gray-300" x-text="d.id"></span></span>
                                            <span>Port: <span class="text-gray-300" x-text="d.port"></span></span>
                                            <span>Runtime: <span class="text-gray-300" x-text="d.type"></span></span>
                                            <span x-show="d.restart_count > 0" class="text-gold">
                                                <i class="fas fa-redo mr-1"></i>Restarts: <span x-text="d.restart_count"></span>
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                <span class="px-6 py-2 rounded-full text-[10px] font-black tracking-[0.2em] uppercase w-fit"
                                      :class="'status-'+d.status" x-text="d.status"></span>
                            </div>
                            <div class="flex flex-wrap gap-3">
                                <button @click="viewDeployment(d.id)" class="btn-luxury px-6 py-2.5 rounded-xl text-[9px] uppercase tracking-[0.2em]">
                                    Details
                                </button>
                                <button @click="viewLogs(d.id)" class="bg-white/5 hover:bg-white/10 px-6 py-2.5 rounded-xl text-[9px] font-bold uppercase tracking-[0.2em] transition-all">
                                    Console
                                </button>
                                <button @click="restartDeploy(d.id)" class="bg-gold/10 hover:bg-gold/20 text-gold px-6 py-2.5 rounded-xl text-[9px] font-bold uppercase tracking-[0.2em] transition-all" x-show="d.status==='running' || d.status==='stopped'">
                                    Restart
                                </button>
                                <button @click="stopDeploy(d.id)" class="bg-red-500/10 hover:bg-red-500/20 text-red-400 px-6 py-2.5 rounded-xl text-[9px] font-bold uppercase tracking-[0.2em] transition-all" x-show="d.status==='running'">
                                    Terminate
                                </button>
                                <button @click="deleteDeploy(d.id)" class="bg-red-900/10 hover:bg-red-900/20 text-red-600 px-6 py-2.5 rounded-xl text-[9px] font-bold uppercase tracking-[0.2em] transition-all ml-auto">
                                    Purge
                                </button>
                            </div>
                        </div>
                    </template>
                    <div x-show="deployments.length===0" class="glass rounded-[40px] p-24 text-center">
                        <div class="w-20 h-20 border border-white/5 flex items-center justify-center mx-auto mb-8 rotate-45">
                            <i class="fas fa-rocket text-gray-700 -rotate-45 text-2xl"></i>
                        </div>
                        <h3 class="text-xl font-heading font-semibold text-white mb-3">No Active Infrastructure</h3>
                        <p class="text-[11px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-10">Your digital portfolio is currently empty.</p>
                        <button @click="navigate('new-deploy')" class="btn-luxury px-10 py-4 rounded-xl text-[10px] uppercase tracking-[0.3em]">
                            Initialize First Deploy
                        </button>
                    </div>
                </div>
            </div>

            <!-- NEW DEPLOY PAGE -->
            <div x-show="currentPage==='new-deploy'" x-transition:enter="transition ease-out duration-500" x-transition:enter-start="opacity-0 translate-y-8" x-transition:enter-end="opacity-100 translate-y-0">
                <div class="mb-12">
                    <span class="text-gold text-[10px] font-bold uppercase tracking-[0.4em] mb-3 block">Creation Suite</span>
                    <h1 class="text-4xl md:text-5xl font-heading font-semibold text-white tracking-tight">Genesis of Service</h1>
                </div>
                <div class="grid md:grid-cols-2 gap-8">
                    <!-- AI Coder -->
                    <div class="glass rounded-[40px] p-10 relative overflow-hidden group">
                        <div class="absolute -top-10 -right-10 w-40 h-40 border border-gold/5 rounded-full group-hover:scale-110 transition-transform duration-700"></div>
                        <div class="flex items-center gap-4 mb-8">
                            <div class="w-14 h-14 border border-purple-500/30 flex items-center justify-center rotate-45 bg-purple-500/5 transition-all group-hover:border-purple-500">
                                <i class="fas fa-brain text-purple-400 -rotate-45 text-lg"></i>
                            </div>
                            <div>
                                <h3 class="font-bold uppercase tracking-widest text-white">Neural Genesis</h3>
                                <p class="text-[9px] text-gray-500 font-bold uppercase tracking-[0.2em] mt-1">AI Guided Architecture</p>
                            </div>
                        </div>
                        <p class="text-sm text-gray-400 leading-relaxed font-light mb-10">Articulate your vision through natural language, and our elite neural engine will manifest the underlying architecture and codebase with absolute precision.</p>
                        <button @click="navigate('ai-coder')" class="w-full bg-purple-600/10 hover:bg-purple-600/20 text-purple-400 border border-purple-600/30 py-4 rounded-xl text-[10px] font-bold uppercase tracking-[0.3em] transition-all">
                            Initialize AI Dialogue
                        </button>
                    </div>

                    <!-- Direct Paste -->
                    <div class="glass rounded-[40px] p-10 relative overflow-hidden group">
                        <div class="absolute -top-10 -right-10 w-40 h-40 border border-gold/5 rounded-full group-hover:scale-110 transition-transform duration-700"></div>
                        <div class="flex items-center gap-4 mb-8">
                            <div class="w-14 h-14 border border-gold/30 flex items-center justify-center rotate-45 bg-gold/5 transition-all group-hover:border-gold">
                                <i class="fas fa-code text-gold -rotate-45 text-lg"></i>
                            </div>
                            <div>
                                <h3 class="font-bold uppercase tracking-widest text-white">Direct Manifest</h3>
                                <p class="text-[9px] text-gray-500 font-bold uppercase tracking-[0.2em] mt-1">Immediate Code Broadcast</p>
                            </div>
                        </div>
                        <p class="text-sm text-gray-400 leading-relaxed font-light mb-10">Transcribe your existing codebase directly into our secure broadcast interface for instantaneous global deployment across our cluster.</p>
                        <button @click="navigate('direct-deploy')" class="w-full btn-luxury py-4 rounded-xl text-[10px] uppercase tracking-[0.3em]">
                            Manifest Infrastructure
                        </button>
                    </div>

                    <!-- File Upload -->
                    <div class="glass rounded-[40px] p-10">
                        <div class="flex items-center gap-4 mb-8">
                            <div class="w-14 h-14 border border-blue-500/30 flex items-center justify-center rotate-45 bg-blue-500/5 transition-all group-hover:border-blue-500">
                                <i class="fas fa-cloud-arrow-up text-blue-400 -rotate-45 text-lg"></i>
                            </div>
                            <div>
                                <h3 class="font-bold uppercase tracking-widest text-white">Dossier Import</h3>
                                <p class="text-[9px] text-gray-500 font-bold uppercase tracking-[0.2em] mt-1">Bulk Artifact Ingestion</p>
                            </div>
                        </div>
                        <div id="dropZone"
                            class="border border-dashed border-white/10 rounded-2xl p-12 text-center cursor-pointer hover:border-gold/40 hover:bg-gold/[0.02] transition-all duration-500 mb-8"
                            onclick="document.getElementById('fileInput').click()"
                            ondragover="event.preventDefault();this.classList.add('border-gold')"
                            ondragleave="this.classList.remove('border-gold')"
                            ondrop="handleDrop(event)">
                            <i class="fas fa-file-invoice text-3xl text-gray-700 mb-6"></i>
                            <p class="text-gray-300 font-bold uppercase tracking-[0.2em] text-[10px] mb-2">Ingest File Artifacts</p>
                            <p class="text-[9px] text-gray-600 font-bold tracking-widest uppercase">PYTHON, NODEJS, ZIP — MAX 100MB</p>
                            <input type="file" id="fileInput" class="hidden" accept=".py,.js,.zip" @change="uploadFile($event)">
                        </div>
                        <div x-show="uploadProgress > 0" class="mb-8">
                            <div class="flex justify-between text-[9px] font-black tracking-widest uppercase mb-3">
                                <span class="text-gray-500">Transmission Progress</span>
                                <span class="text-gold" x-text="uploadProgress+'%'"></span>
                            </div>
                            <div class="bg-white/5 rounded-full h-1 overflow-hidden">
                                <div class="progress-bar" :style="'width:'+uploadProgress+'%'"></div>
                            </div>
                        </div>
                        <div class="bg-gold/5 border border-gold/10 rounded-2xl p-5 text-[10px] text-gold font-bold tracking-widest uppercase flex items-center gap-4">
                            <i class="fas fa-info-circle"></i>
                            <span>Cost: 0.5 CR · Automated dependency resolution enabled</span>
                        </div>
                    </div>

                    <!-- GitHub Deploy -->
                    <div class="glass rounded-[40px] p-10">
                        <div class="flex items-center gap-4 mb-8">
                            <div class="w-14 h-14 border border-white/20 flex items-center justify-center rotate-45 bg-white/5 transition-all group-hover:border-white">
                                <i class="fab fa-github text-white -rotate-45 text-lg"></i>
                            </div>
                            <div>
                                <h3 class="font-bold uppercase tracking-widest text-white">Repository Sync</h3>
                                <p class="text-[9px] text-gray-500 font-bold uppercase tracking-[0.2em] mt-1">Continuous Integration Link</p>
                            </div>
                        </div>
                        <form @submit.prevent="deployGithub()" class="space-y-6">
                            <div>
                                <label class="text-[9px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-3 block">Repository URI</label>
                                <input type="url" x-model="githubForm.url" required placeholder="https://github.com/organization/manifest"
                                    class="w-full px-6 py-4 bg-black/40 border border-white/5 rounded-xl text-white text-xs placeholder-gray-700 focus:outline-none focus:border-gold transition-all">
                            </div>
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="text-[9px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-3 block">Branch Dossier</label>
                                    <input type="text" x-model="githubForm.branch" placeholder="main"
                                        class="w-full px-6 py-4 bg-black/40 border border-white/5 rounded-xl text-white text-xs placeholder-gray-700 focus:outline-none focus:border-gold transition-all">
                                </div>
                                <div>
                                    <label class="text-[9px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-3 block">Build Script</label>
                                    <input type="text" x-model="githubForm.buildCmd" placeholder="npm run build"
                                        class="w-full px-6 py-4 bg-black/40 border border-white/5 rounded-xl text-white text-xs placeholder-gray-700 focus:outline-none focus:border-gold transition-all">
                                </div>
                            </div>
                            <button type="submit" :disabled="deploying"
                                class="w-full btn-luxury py-4 rounded-xl text-[10px] uppercase tracking-[0.3em] transition-all">
                                <span x-show="!deploying"><i class="fab fa-github mr-3"></i>Link Repository <span class="opacity-60">(1.0 CR)</span></span>
                                <span x-show="deploying"><i class="fas fa-spinner fa-spin mr-3"></i>Synchronizing...</span>
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- AI CODER PAGE -->
            <div x-show="currentPage==='ai-coder'" x-transition:enter="transition ease-out duration-500" x-transition:enter-start="opacity-0 translate-y-8" x-transition:enter-end="opacity-100 translate-y-0">
                <div class="flex items-center gap-6 mb-12">
                    <button @click="navigate('new-deploy')" class="w-10 h-10 border border-white/10 flex items-center justify-center hover:border-gold transition-colors">
                        <i class="fas fa-chevron-left text-xs"></i>
                    </button>
                    <h1 class="text-3xl font-heading font-semibold">Neural Genesis</h1>
                </div>
                <div class="glass rounded-[40px] p-10 mb-10">
                    <div class="flex items-center gap-4 mb-10">
                        <div class="w-14 h-14 border border-purple-500/30 flex items-center justify-center rotate-45 bg-purple-500/5 animate-pulse">
                            <i class="fas fa-robot text-purple-400 -rotate-45 text-lg"></i>
                        </div>
                        <div>
                            <h3 class="font-bold uppercase tracking-widest text-white">Project Articulation</h3>
                            <p class="text-[9px] text-gray-500 font-bold uppercase tracking-[0.2em] mt-1">Direct Communication with Neural Cluster</p>
                        </div>
                    </div>
                    <textarea x-model="aiPrompt" rows="5"
                        class="w-full px-8 py-6 bg-black/40 border border-white/5 rounded-3xl text-white placeholder-gray-700 focus:outline-none focus:border-purple-500 transition-all text-sm leading-relaxed font-light mb-8"
                        placeholder="Define the parameters of your desired application..."></textarea>
                    <button @click="generateAICode()" :disabled="aiGenerating"
                        class="w-full bg-purple-600/10 hover:bg-purple-600/20 text-purple-400 border border-purple-600/30 py-5 rounded-xl text-[10px] font-bold uppercase tracking-[0.3em] transition-all">
                        <span x-show="!aiGenerating"><i class="fas fa-wand-magic-sparkles mr-3"></i>Synthesize Architecture</span>
                        <span x-show="aiGenerating"><i class="fas fa-spinner fa-spin mr-3"></i>Neural Inversion in Progress...</span>
                    </button>
                </div>
                <div x-show="generatedCode" class="fade-in">
                    <div class="flex justify-between items-center mb-4 px-2">
                        <h3 class="text-[9px] font-black text-gray-500 uppercase tracking-[0.4em]">Synthesized Output</h3>
                        <button @click="copyCode(generatedCode)" class="text-gold text-[9px] font-bold uppercase tracking-[0.2em] hover:tracking-[0.3em] transition-all">
                            <i class="fas fa-copy mr-2"></i>Copy Manifest
                        </button>
                    </div>
                    <div class="bg-black border border-white/5 rounded-[32px] p-8 mb-10 font-mono text-xs shadow-2xl">
                        <textarea x-model="generatedCode"
                            class="w-full h-[500px] bg-transparent text-purple-100/80 focus:outline-none resize-none custom-scrollbar leading-relaxed"
                            placeholder="Awaiting synthesis..."></textarea>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div class="md:col-span-2 bg-white/[0.02] border border-white/5 p-6 rounded-2xl flex items-center gap-6">
                            <label class="text-[9px] font-black text-gray-500 uppercase tracking-[0.3em] whitespace-nowrap">File Identifier</label>
                            <input type="text" x-model="aiFilename"
                                class="w-full bg-transparent border-b border-white/10 py-2 text-white focus:outline-none focus:border-gold transition-colors text-sm font-mono">
                        </div>
                        <button @click="deployRawCode(generatedCode, aiFilename)" :disabled="deploying"
                            class="btn-luxury rounded-xl text-[10px] uppercase tracking-[0.3em] transition-all">
                            Authorize Deployment <span class="opacity-60 ml-2">(0.5 CR)</span>
                        </button>
                    </div>
                </div>
            </div>

            <!-- DIRECT DEPLOY PAGE -->
            <div x-show="currentPage==='direct-deploy'" x-transition:enter="transition ease-out duration-500" x-transition:enter-start="opacity-0 translate-y-8" x-transition:enter-end="opacity-100 translate-y-0">
                <div class="flex items-center gap-6 mb-12">
                    <button @click="navigate('new-deploy')" class="w-10 h-10 border border-white/10 flex items-center justify-center hover:border-gold transition-colors">
                        <i class="fas fa-chevron-left text-xs"></i>
                    </button>
                    <h1 class="text-3xl font-heading font-semibold">Direct Manifest</h1>
                </div>
                <div class="glass rounded-[40px] p-10">
                    <div class="mb-10">
                        <label class="text-[9px] font-black text-gray-500 uppercase tracking-[0.4em] mb-6 block px-2">Source Code Transcription</label>
                        <textarea x-model="directCode" rows="15"
                            class="w-full px-8 py-8 bg-black/60 border border-white/5 rounded-[32px] text-gold/80 font-mono text-xs focus:outline-none focus:border-gold/30 transition-all leading-relaxed custom-scrollbar"
                            placeholder="Transcribe code artifacts here..."></textarea>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                        <div class="md:col-span-2 bg-white/[0.02] border border-white/5 p-6 rounded-2xl flex items-center gap-6">
                            <label class="text-[9px] font-black text-gray-500 uppercase tracking-[0.3em] whitespace-nowrap">Project Alias</label>
                            <input type="text" x-model="directFilename" placeholder="manifest.py"
                                class="w-full bg-transparent border-b border-white/10 py-2 text-white focus:outline-none focus:border-gold transition-colors text-sm font-mono">
                        </div>
                        <button @click="deployRawCode(directCode, directFilename)" :disabled="deploying || !directCode"
                            class="btn-luxury py-4 rounded-xl text-[10px] uppercase tracking-[0.3em] transition-all">
                            Authorize Manifest <span class="opacity-60 ml-2">(0.5 CR)</span>
                        </button>
                    </div>
                    <div class="bg-gold/5 border border-gold/10 rounded-2xl p-6 flex gap-6 text-[10px] text-gold font-bold tracking-[0.2em] uppercase leading-relaxed">
                        <i class="fas fa-shield-halved text-lg"></i>
                        <p>Our secure ingestion pipeline will automatically isolate dependencies and containerize the environment. Absolute technical integrity is guaranteed.</p>
                    </div>
                </div>
            </div>

            <!-- BUY CREDITS PAGE -->
            <div x-show="currentPage==='buy-credits'" x-transition:enter="transition ease-out duration-500" x-transition:enter-start="opacity-0 translate-y-8" x-transition:enter-end="opacity-100 translate-y-0">
                <div class="mb-12">
                    <span class="text-gold text-[10px] font-bold uppercase tracking-[0.4em] mb-3 block">Financial Treasury</span>
                    <h1 class="text-4xl md:text-5xl font-heading font-semibold text-white tracking-tight">Acquire Capital</h1>
                </div>
                <div class="grid md:grid-cols-3 gap-8 mb-12">
                    <div class="glass rounded-[40px] p-10 hover:border-gold/30 transition-all cursor-pointer group" @click="selectPackage('10_credits')">
                        <div class="flex justify-between items-start mb-10">
                            <div class="w-14 h-14 border border-gold/20 flex items-center justify-center rotate-45 group-hover:border-gold transition-all">
                                <i class="fas fa-gem text-gold -rotate-45 text-sm"></i>
                            </div>
                            <span class="text-[9px] font-black tracking-widest text-gold/60 border border-gold/20 px-3 py-1 rounded-full uppercase">Starter</span>
                        </div>
                        <div class="text-4xl font-heading font-light text-white mb-2">10 Credits</div>
                        <div class="text-2xl text-gold font-light mb-8">₹50</div>
                        <div class="sep-line mb-8"></div>
                        <ul class="text-[10px] font-bold tracking-widest text-gray-500 uppercase space-y-4 mb-10">
                            <li><i class="fas fa-check text-gold/40 mr-3"></i>20 Refined Deploys</li>
                            <li><i class="fas fa-check text-gold/40 mr-3"></i>10 Cluster Syncs</li>
                            <li><i class="fas fa-check text-gold/40 mr-3"></i>20 Snapshots</li>
                        </ul>
                        <button class="w-full border border-gold/30 text-gold py-4 rounded-xl text-[10px] font-bold uppercase tracking-[0.3em] group-hover:bg-gold group-hover:text-black transition-all">Select Tier</button>
                    </div>

                    <div class="luxury-card rounded-[40px] p-10 relative border-gold shadow-[0_20px_40px_rgba(212,175,55,0.1)] transform scale-105 z-10">
                        <div class="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-gold text-black text-[9px] font-black uppercase tracking-[0.4em] px-8 py-2.5">Distinguished Choice</div>
                        <div class="flex justify-between items-start mb-10">
                            <div class="w-14 h-14 border border-gold/40 flex items-center justify-center rotate-45 bg-gold/5">
                                <i class="fas fa-crown text-gold -rotate-45 text-sm"></i>
                            </div>
                            <span class="text-[9px] font-black tracking-widest text-gold border border-gold/40 px-3 py-1 rounded-full uppercase">Professional</span>
                        </div>
                        <div class="text-4xl font-heading font-light text-white mb-2">99 Credits</div>
                        <div class="text-2xl text-gold font-light mb-1">₹399</div>
                        <div class="text-[10px] text-gold/60 font-black italic tracking-widest mb-8 uppercase"><s class="opacity-40">₹495</s> — Save ₹96</div>
                        <div class="sep-line mb-8"></div>
                        <ul class="text-[10px] font-bold tracking-widest text-gray-300 uppercase space-y-4 mb-10">
                            <li><i class="fas fa-check text-gold mr-3"></i>198 Refined Deploys</li>
                            <li><i class="fas fa-check text-gold mr-3"></i>99 Cluster Syncs</li>
                            <li><i class="fas fa-check text-gold mr-3"></i>198 Snapshots</li>
                            <li><i class="fas fa-star text-gold mr-3"></i>Concierge Priority</li>
                        </ul>
                        <button @click="selectPackage('99_credits')" class="w-full btn-luxury py-5 rounded-xl text-[10px] uppercase tracking-[0.3em]">Acquire Tier</button>
                    </div>

                    <div class="glass rounded-[40px] p-10 hover:border-gold/30 transition-all">
                        <div class="flex justify-between items-start mb-10">
                            <div class="w-14 h-14 border border-gold/20 flex items-center justify-center rotate-45">
                                <i class="fas fa-infinity text-gold -rotate-45 text-sm"></i>
                            </div>
                            <span class="text-[9px] font-black tracking-widest text-gold/60 border border-gold/20 px-3 py-1 rounded-full uppercase">Bespoke</span>
                        </div>
                        <div class="text-4xl font-heading font-light text-white mb-2">Custom</div>
                        <div class="text-2xl text-gold font-light mb-8">Tailored Value</div>
                        <div class="mb-8">
                            <label class="text-[9px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-3 block px-2">Investment Amount (₹)</label>
                            <input type="number" x-model="customAmount" placeholder="Min 10" min="10"
                                class="w-full px-6 py-4 bg-black/40 border border-white/5 rounded-xl text-white text-xs focus:outline-none focus:border-gold transition-all">
                        </div>
                        <p class="text-[10px] text-gray-500 font-medium tracking-wide mb-10 italic">
                            For institutional scale requirements, initiate a dialogue with <a href="{{ telegram_link }}" target="_blank" class="text-gold hover:underline">Support</a>.
                        </p>
                        <button @click="selectCustomPackage()" class="w-full bg-white/5 hover:bg-white/10 text-white border border-white/10 py-4 rounded-xl text-[10px] font-bold uppercase tracking-[0.3em] transition-all">
                            Proceed to Invoicing
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Payment Modal -->
    <div x-show="modal==='payment'" x-cloak @click.self="modal=null"
         class="fixed inset-0 bg-black/95 backdrop-blur-md z-50 flex items-center justify-center p-6">
        <div class="glass rounded-[40px] max-w-md w-full p-10 max-h-[90vh] overflow-y-auto">
            <div class="flex items-center justify-between mb-8">
                <h2 class="text-xl font-heading font-semibold tracking-wide">Capital Acquisition</h2>
                <button @click="modal=null" class="text-gray-500 hover:text-white transition-colors">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="bg-white/[0.03] border border-white/5 rounded-2xl p-6 mb-8 text-[11px] font-bold uppercase tracking-widest space-y-4">
                <div class="flex justify-between items-center"><span class="text-gray-500">Tier</span><span class="text-white" x-text="paymentData.package"></span></div>
                <div class="flex justify-between items-center"><span class="text-gray-500">Assets</span><span class="text-gold" x-text="paymentData.credits + ' CR'"></span></div>
                <div class="sep-line opacity-50"></div>
                <div class="flex justify-between items-center"><span class="text-gray-500">Investment</span><span class="text-2xl font-heading font-light text-white">₹<span x-text="paymentData.price"></span></span></div>
            </div>
            <div class="bg-white rounded-3xl p-6 mb-8 text-center shadow-[0_0_30px_rgba(255,255,255,0.05)]">
                <img src="/qr.jpg" alt="QR" class="w-48 h-48 mx-auto object-contain">
                <p class="text-black font-black text-[10px] tracking-[0.2em] mt-4 uppercase">Secure Payment Gateway</p>
            </div>
            <div class="space-y-6 mb-8">
                <div>
                    <label class="text-[9px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-3 block px-1">Proof of Investment</label>
                    <input type="file" accept="image/*" @change="uploadScreenshot($event)"
                        class="w-full text-[10px] text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:bg-gold/10 file:text-gold file:text-[9px] file:font-black file:uppercase file:tracking-widest cursor-pointer">
                </div>
                <div>
                    <label class="text-[9px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-3 block px-1">Transaction ID / UTR</label>
                    <input type="text" x-model="paymentData.transactionId" placeholder="Enter Reference ID" required
                        class="w-full px-6 py-4 bg-black/40 border border-white/5 rounded-xl text-white text-xs focus:outline-none focus:border-gold transition-all">
                </div>
            </div>
            <div class="bg-gold/5 border border-gold/10 rounded-xl p-4 text-[9px] text-gold font-bold tracking-widest uppercase mb-8 flex items-center gap-3">
                <i class="fas fa-clock animate-pulse"></i>
                <span>Session Expiry: <strong x-text="formatTime(timeRemaining)"></strong></span>
            </div>
            <div class="flex gap-4">
                <button @click="modal=null" class="flex-1 bg-white/5 hover:bg-white/10 py-4 rounded-xl text-[10px] font-bold uppercase tracking-[0.2em] transition-all">Cancel</button>
                <button @click="submitPayment()" class="flex-1 btn-luxury py-4 rounded-xl text-[10px] uppercase tracking-[0.2em]">Verify</button>
            </div>
        </div>
    </div>

    <!-- Deployment Details Modal -->
    <div x-show="modal==='details'" x-cloak @click.self="modal=null"
         class="fixed inset-0 bg-black/95 backdrop-blur-md z-50 flex items-center justify-center p-6">
        <div class="glass rounded-[40px] max-w-5xl w-full max-h-[90vh] overflow-hidden flex flex-col">
            <div class="p-10 border-b border-white/5 flex items-center justify-between">
                <div class="flex items-center gap-6">
                    <div class="w-12 h-12 border border-gold/30 flex items-center justify-center rotate-45 bg-gold/5">
                        <i class="fas fa-rocket text-gold -rotate-45 text-sm"></i>
                    </div>
                    <div>
                        <h2 class="text-xl font-heading font-semibold tracking-wide text-white uppercase" x-text="selectedDeploy && selectedDeploy.name"></h2>
                        <p class="text-[9px] text-gray-500 font-bold uppercase tracking-[0.4em] mt-1" x-text="selectedDeploy && selectedDeploy.id"></p>
                    </div>
                </div>
                <button @click="modal=null" class="text-gray-500 hover:text-white p-2 transition-colors">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
            <div class="flex-1 overflow-y-auto p-10 custom-scrollbar">
                <!-- Tabs -->
                <div class="flex gap-2 mb-10 bg-white/[0.02] p-1.5 rounded-2xl border border-white/5">
                    <template x-for="tab in ['dossier','environment','artifacts','backup','console']" :key="tab">
                        <button @click="detailsTab=tab"
                            :class="detailsTab===tab ? 'bg-gold text-black shadow-lg shadow-gold/20' : 'text-gray-500 hover:text-white'"
                            class="flex-1 py-3 rounded-xl text-[9px] font-black uppercase tracking-[0.2em] transition-all duration-300"
                            x-text="tab"></button>
                    </template>
                </div>

                <div x-show="detailsTab==='dossier'" class="space-y-6 animate-fade-in">
                    <div class="grid grid-cols-2 md:grid-cols-3 gap-6">
                        <template x-for="[label, val] in [['Identifier', selectedDeploy?.id],['Assigned Port', selectedDeploy?.port],['Current State', selectedDeploy?.status],['Runtime', selectedDeploy?.type],['Process ID', selectedDeploy?.pid],['Recycles', selectedDeploy?.restart_count]]" :key="label">
                            <div class="bg-white/[0.02] border border-white/5 rounded-2xl p-6">
                                <div class="text-[9px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-3" x-text="label"></div>
                                <div class="font-mono text-xs font-semibold text-white tracking-wider" x-text="val"></div>
                            </div>
                        </template>
                    </div>
                    <div x-show="selectedDeploy?.dependencies?.length > 0" class="pt-6">
                        <p class="text-[9px] font-bold uppercase tracking-[0.3em] text-gray-500 mb-4 px-2">Manifest Dependencies</p>
                        <div class="flex flex-wrap gap-2">
                            <template x-for="dep in selectedDeploy?.dependencies" :key="dep">
                                <span class="bg-gold/5 text-gold border border-gold/10 px-4 py-1.5 rounded-full text-[10px] font-bold tracking-widest" x-text="dep"></span>
                            </template>
                        </div>
                    </div>
                </div>

                <div x-show="detailsTab==='environment'" class="animate-fade-in">
                    <div class="flex gap-4 mb-8">
                        <input x-model="newEnv.key" placeholder="VARIABLE_KEY" class="flex-1 px-6 py-4 bg-black/40 border border-white/5 rounded-xl text-white text-xs focus:outline-none focus:border-gold transition-all font-mono">
                        <input x-model="newEnv.value" placeholder="parameter_value" class="flex-1 px-6 py-4 bg-black/40 border border-white/5 rounded-xl text-white text-xs focus:outline-none focus:border-gold transition-all font-mono">
                        <button @click="addEnvVar()" class="btn-luxury px-8 rounded-xl">
                            <i class="fas fa-plus"></i>
                        </button>
                    </div>
                    <div class="space-y-3">
                        <template x-for="[k, v] in Object.entries(selectedDeploy?.env_vars || {})" :key="k">
                            <div class="bg-white/[0.02] border border-white/5 rounded-2xl p-5 flex items-center justify-between group hover:border-gold/20 transition-all">
                                <div class="font-mono text-xs"><span class="text-gold" x-text="k"></span> <span class="text-gray-600 mx-3">→</span> <span class="text-white" x-text="v"></span></div>
                                <button @click="deleteEnvVar(k)" class="text-gray-700 hover:text-red-500 transition-colors p-2"><i class="fas fa-trash-can text-xs"></i></button>
                            </div>
                        </template>
                        <div x-show="!selectedDeploy?.env_vars || Object.keys(selectedDeploy?.env_vars).length===0" class="text-center py-16 text-gray-600 text-[10px] font-bold uppercase tracking-[0.3em]">No environmental parameters configured</div>
                    </div>
                </div>

                <div x-show="detailsTab==='artifacts'" class="animate-fade-in">
                    <div class="flex justify-between items-center mb-8 px-2">
                        <p class="text-[9px] font-bold uppercase tracking-[0.3em] text-gray-500">Infrastructure Artifacts</p>
                        <button @click="loadFiles()" class="text-gold text-[9px] font-bold uppercase tracking-[0.2em] hover:tracking-[0.3em] transition-all">
                            <i class="fas fa-sync-alt mr-2"></i>Refresh Registry
                        </button>
                    </div>
                    <div class="space-y-2 max-h-[400px] overflow-y-auto custom-scrollbar pr-4">
                        <template x-for="file in deployFiles" :key="file.path">
                            <div class="bg-white/[0.02] border border-white/5 rounded-xl p-5 flex items-center justify-between hover:bg-white/[0.04] transition-all">
                                <div class="flex items-center gap-5">
                                    <i class="fas fa-file-code text-gray-600 text-sm"></i>
                                    <div>
                                        <div class="font-mono text-xs text-white" x-text="file.path"></div>
                                        <div class="text-[9px] text-gray-600 font-bold uppercase tracking-widest mt-1" x-text="formatBytes(file.size)"></div>
                                    </div>
                                </div>
                                <div class="text-[9px] text-gray-600 font-bold tracking-widest" x-text="formatDate(file.modified)"></div>
                            </div>
                        </template>
                        <div x-show="deployFiles.length===0" class="text-center py-16 text-gray-600 text-[10px] font-bold uppercase tracking-[0.3em]">No artifact records found</div>
                    </div>
                </div>

                <div x-show="detailsTab==='backup'" class="text-center py-20 animate-fade-in">
                    <div class="w-20 h-20 border border-white/5 flex items-center justify-center mx-auto mb-8 rotate-45 bg-white/[0.01]">
                        <i class="fas fa-archive text-gray-700 -rotate-45 text-2xl"></i>
                    </div>
                    <h3 class="text-xl font-heading font-semibold text-white mb-3 tracking-wide">Archival Registry</h3>
                    <p class="text-[11px] font-medium text-gray-500 mb-10 max-w-xs mx-auto leading-relaxed">Synthesize a complete archival snapshot of this deployment for external cold storage.</p>
                    <button @click="createBackup()" class="btn-luxury px-12 py-4 rounded-xl text-[10px] uppercase tracking-[0.3em]">
                        Initialize Archival <span class="opacity-60 ml-2">(0.5 CR)</span>
                    </button>
                </div>

                <div x-show="detailsTab==='console'" class="animate-fade-in">
                    <div class="bg-black border border-white/5 rounded-3xl p-8 font-mono text-[10px] text-gold/80 h-[450px] overflow-y-auto whitespace-pre-wrap leading-relaxed custom-scrollbar shadow-inner"
                         x-ref="consoleEl" x-text="consoleLogs"></div>
                    <div class="flex flex-wrap items-center gap-4 mt-6">
                        <div class="flex items-center gap-3 bg-white/[0.02] border border-white/5 rounded-full px-5 py-2">
                            <div class="w-1.5 h-1.5 rounded-full animate-pulse" :class="sseConnected ? 'bg-gold shadow-[0_0_10px_rgba(212,175,55,0.5)]' : 'bg-red-500'"></div>
                            <span class="text-[9px] text-gray-500 uppercase font-black tracking-widest" x-text="sseConnected ? 'Direct Link Established' : 'Link Terminated'"></span>
                        </div>
                        <button @click="refreshLogs()" class="text-white bg-white/5 hover:bg-white/10 px-6 py-2.5 rounded-xl text-[9px] font-bold uppercase tracking-[0.2em] transition-all ml-auto">
                            Force Refresh
                        </button>
                        <button @click="consoleLogs=''" class="text-gray-600 hover:text-white text-[9px] font-bold uppercase tracking-[0.2em] transition-all px-4">
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

            // AI & Direct
            aiPrompt: '',
            aiGenerating: false,
            generatedCode: '',
            aiFilename: 'main.py',
            directCode: '',
            directFilename: 'app.py',

            navItems: [
                { id:'overview', icon:'fas fa-th-large', label:'Overview', badge:0 },
                { id:'buy-credits', icon:'fas fa-gem', label:'Credits', badge:0 },
                { id:'new-deploy', icon:'fas fa-plus-circle', label:'AI Coder', badge:0 },
                { id:'deployments', icon:'fas fa-rocket', label:'Deploys', badge:0 },
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
                    case 'logs':
                        if (this.selectedDeploy && this.selectedDeploy.id === event.data.id && this.modal === 'details' && this.detailsTab === 'console') {
                            this.consoleLogs += event.data.line;
                            this.$nextTick(() => { if (this.$refs.consoleEl) this.$refs.consoleEl.scrollTop = this.$refs.consoleEl.scrollHeight; });
                        }
                        break;
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

            async generateAICode() {
                if (!this.aiPrompt) return;
                this.aiGenerating = true;
                try {
                    const res = await fetch('/api/ai/generate', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({ prompt: this.aiPrompt })
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.generatedCode = data.code;
                        this.showToast('✨ AI code generated successfully!', 'success');
                    } else { this.showToast('❌ ' + data.error, 'error'); }
                } catch(e) { this.showToast('❌ AI Error', 'error'); }
                finally { this.aiGenerating = false; }
            },

            async deployRawCode(code, filename) {
                if (!code) return;
                this.deploying = true;
                try {
                    const res = await fetch('/api/deploy/raw', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({ code: code, filename: filename })
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.showToast('✅ Deployed successfully!', 'success');
                        this.loadDeployments();
                        this.currentPage = 'deployments';
                        this.directCode = '';
                    } else { this.showToast('❌ ' + data.error, 'error'); }
                } catch(e) { this.showToast('❌ Deployment failed', 'error'); }
                finally { this.deploying = false; }
            },

            copyCode(text) {
                navigator.clipboard.writeText(text).then(() => {
                    this.showToast('📋 Copied to clipboard!', 'info');
                });
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
    <title>EliteHost — Admin Concierge</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap" rel="stylesheet">
    <style>
        :root { --gold: #d4af37; --gold-dark: #b8860b; --black: #0a0a0a; --charcoal: #141414; }
        body{
            font-family: 'Inter', sans-serif;
            background: var(--black);
            color: #e5e5e5;
        }
        h1, h2, h3, h4 { font-family: 'Plus Jakarta Sans', sans-serif; }
        .glass{background:rgba(20, 20, 20, 0.7);backdrop-filter:blur(20px);border:1px solid rgba(212, 175, 55, 0.1);}
        ::-webkit-scrollbar{width:4px;height:4px}
        ::-webkit-scrollbar-thumb{background:var(--gold-dark);border-radius:2px}
        .btn-luxury{background:linear-gradient(135deg,var(--gold),var(--gold-dark)); color:var(--black); font-weight:700; transition:all .3s ease;}
        .btn-luxury:hover{filter:brightness(1.1); transform:translateY(-1px);}
    </style>
</head>
<body class="text-white min-h-screen" x-data="adminApp()">
    <div class="bg-black border-b border-white/5 p-8 sticky top-0 z-50 backdrop-blur-xl">
        <div class="max-w-7xl mx-auto flex items-center justify-between">
            <div class="flex items-center gap-6">
                <div class="w-14 h-14 border border-gold flex items-center justify-center rotate-45 bg-gold/5 shadow-[0_0_20px_rgba(212,175,55,0.15)]">
                    <i class="fas fa-crown text-gold -rotate-45 text-lg"></i>
                </div>
                <div>
                    <h1 class="text-2xl font-heading font-semibold tracking-tight uppercase">Administrative <span class="text-gold">Concierge</span></h1>
                    <div class="flex items-center gap-3 mt-1">
                        <span class="w-1.5 h-1.5 bg-gold rounded-full animate-pulse shadow-[0_0_10px_rgba(212,175,55,0.5)]"></span>
                        <p class="text-gold/40 text-[9px] font-bold uppercase tracking-[0.4em]">System Integrity Maintained</p>
                    </div>
                </div>
            </div>
            <div class="flex gap-4">
                <a href="/dashboard" class="bg-white/5 hover:bg-white/10 border border-white/10 px-8 py-3 rounded-xl text-[10px] font-bold uppercase tracking-[0.2em] transition-all flex items-center gap-3">
                    <i class="fas fa-chevron-left text-[8px]"></i> Exit to Dashboard
                </a>
            </div>
        </div>
    </div>

    <div class="max-w-7xl mx-auto p-10">
        <!-- Stats -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8 mb-12">
            <div class="glass rounded-3xl p-8 border-l-2 border-gold/50">
                <div class="text-gray-500 text-[9px] font-bold uppercase tracking-[0.3em] mb-4 px-1">Total Clientele</div>
                <div class="text-4xl font-heading font-light">{{ stats.total_users }}</div>
            </div>
            <div class="glass rounded-3xl p-8 border-l-2 border-gold/50">
                <div class="text-gray-500 text-[9px] font-bold uppercase tracking-[0.3em] mb-4 px-1">Infrastructure Records</div>
                <div class="text-4xl font-heading font-light text-gold">{{ stats.total_deployments }}</div>
            </div>
            <div class="glass rounded-3xl p-8 border-l-2 border-gold/50">
                <div class="text-gray-500 text-[9px] font-bold uppercase tracking-[0.3em] mb-4 px-1">Active Presences</div>
                <div class="text-4xl font-heading font-light text-green-500">{{ stats.active_processes }}</div>
            </div>
            <div class="glass rounded-3xl p-8 border-l-2 border-gold/50">
                <div class="text-gray-500 text-[9px] font-bold uppercase tracking-[0.3em] mb-4 px-1">Pending Invoices</div>
                <div class="text-4xl font-heading font-light text-gold">{{ stats.pending_payments }}</div>
            </div>
        </div>

        <!-- System Metrics -->
        <div class="glass rounded-[40px] p-10 mb-12">
            <h2 class="text-xl font-heading font-semibold text-white mb-10 tracking-wide">Infrastructure Resource Utilization</h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-10">
                <template x-for="[label, key, color] in [['Neural Computation','cpu','bg-gold'],['Allocated Memory','memory_percent','bg-gold/50'],['Storage Matrix','disk_percent','bg-gold/30']]" :key="key">
                    <div>
                        <div class="flex justify-between items-end text-[10px] font-bold uppercase tracking-[0.2em] mb-4">
                            <span class="text-gray-500" x-text="label"></span>
                            <span class="text-white" x-text="(metrics[key]||0)+'%'"></span>
                        </div>
                        <div class="bg-white/5 rounded-full h-1 overflow-hidden">
                            <div :class="color" class="h-full rounded-full transition-all duration-[2s]"
                                 :style="'width:'+(metrics[key]||0)+'%'"></div>
                        </div>
                    </div>
                </template>
            </div>
            <div class="grid grid-cols-3 gap-8 mt-10 text-[9px] font-bold uppercase tracking-[0.3em] text-gray-500">
                <div class="flex items-center gap-3"><i class="fas fa-memory text-gold/30"></i> RAM: <span class="text-white ml-auto" x-text="(metrics.memory_used||0)+'/'+( metrics.memory_total||0)+' GB'"></span></div>
                <div class="flex items-center gap-3"><i class="fas fa-hard-drive text-gold/30"></i> DISK: <span class="text-white ml-auto" x-text="(metrics.disk_used||0)+'/'+(metrics.disk_total||0)+' GB'"></span></div>
                <div class="flex items-center gap-3"><i class="fas fa-network-wired text-gold/30"></i> NET: <span class="text-white ml-auto" x-text="'↑'+(metrics.net_sent_mb||0)+'M ↓'+(metrics.net_recv_mb||0)+'M'"></span></div>
            </div>
        </div>

        <!-- Users -->
        <div class="glass rounded-[40px] mb-12 overflow-hidden border-gold/5">
            <div class="p-8 border-b border-white/5 flex items-center justify-between">
                <h2 class="text-xl font-heading font-semibold text-white tracking-wide uppercase">Client Registry</h2>
                <span class="text-[10px] font-bold uppercase tracking-[0.3em] text-gold/40">{{ users|length }} Total Entitites</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead class="bg-white/[0.02] text-[9px] font-black uppercase tracking-[0.3em] text-gray-500">
                        <tr>
                            <th class="text-left p-8">Identity</th>
                            <th class="text-left p-8">Capital Assets</th>
                            <th class="text-left p-8">Infrastructure</th>
                            <th class="text-left p-8">Onboarding</th>
                            <th class="text-left p-8">Clearance</th>
                            <th class="text-left p-8">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="text-[11px] font-medium tracking-wide">
                        {% for user in users %}
                        <tr class="border-b border-white/5 hover:bg-white/[0.01] transition-all">
                            <td class="p-8 font-bold uppercase text-white">{{ user.email }}</td>
                            <td class="p-8 text-gold font-mono">{{ user.credits }} CR</td>
                            <td class="p-8 text-gray-400">{{ user.deployments|length }} Records</td>
                            <td class="p-8 text-gray-500">{{ user.created_at[:10] }}</td>
                            <td class="p-8">
                                {% if user.is_banned %}
                                <span class="px-4 py-1.5 bg-red-900/10 text-red-500 border border-red-900/20 rounded-full text-[9px] font-black tracking-widest uppercase">Revoked</span>
                                {% else %}
                                <span class="px-4 py-1.5 bg-green-900/10 text-green-500 border border-green-900/20 rounded-full text-[9px] font-black tracking-widest uppercase">Cleared</span>
                                {% endif %}
                            </td>
                            <td class="p-8">
                                <div class="flex gap-4">
                                    <button onclick="addCreditsPrompt('{{ user.id }}')"
                                        class="bg-gold/10 hover:bg-gold text-gold hover:text-black border border-gold/20 px-5 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all">
                                        Asset Grant
                                    </button>
                                    {% if not user.is_banned %}
                                    <button onclick="banUser('{{ user.id }}')"
                                        class="bg-red-900/10 hover:bg-red-600 text-red-500 hover:text-white border border-red-900/20 px-5 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all">
                                        Revoke
                                    </button>
                                    {% else %}
                                    <button onclick="unbanUser('{{ user.id }}')"
                                        class="bg-green-900/10 hover:bg-green-600 text-green-500 hover:text-white border border-green-900/20 px-5 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all">
                                        Restore
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
        <div class="glass rounded-[40px] overflow-hidden border-gold/5">
            <div class="p-8 border-b border-white/5 flex items-center justify-between">
                <h2 class="text-xl font-heading font-semibold text-white tracking-wide uppercase">Capital Manifests</h2>
                <span class="text-[10px] font-bold uppercase tracking-[0.3em] text-gold/40">{{ payments|length }} Total Transactions</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead class="bg-white/[0.02] text-[9px] font-black uppercase tracking-[0.3em] text-gray-500">
                        <tr>
                            <th class="text-left p-8">Beneficiary</th>
                            <th class="text-left p-8">Capital Volume</th>
                            <th class="text-left p-8">Reference Identifier</th>
                            <th class="text-left p-8">Transmission Date</th>
                            <th class="text-left p-8">Manifest State</th>
                            <th class="text-left p-8">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="text-[11px] font-medium tracking-wide">
                        {% for p in payments %}
                        <tr class="border-b border-white/5 hover:bg-white/[0.01] transition-all">
                            <td class="p-8 font-bold uppercase text-white">{{ p.user_email }}</td>
                            <td class="p-8 text-gold">{{ p.credits }} CR (₹{{ p.price }})</td>
                            <td class="p-8 font-mono text-[10px] text-gray-500">{{ p.transaction_id or '—' }}</td>
                            <td class="p-8 text-gray-600 text-[10px]">{{ p.created_at[:16] }}</td>
                            <td class="p-8">
                                <span class="px-4 py-1.5 rounded-full text-[9px] font-black tracking-widest uppercase border
                                    {% if p.status == 'approved' %}bg-green-900/10 text-green-500 border-green-900/20
                                    {% elif p.status == 'submitted' %}bg-gold/10 text-gold border-gold/20
                                    {% elif p.status == 'pending' %}bg-white/5 text-gray-400 border-white/10
                                    {% elif p.status == 'expired' %}bg-red-900/10 text-gray-600 border-red-900/10
                                    {% else %}bg-red-900/10 text-red-500 border-red-900/20{% endif %}">
                                    {{ p.status }}
                                </span>
                            </td>
                            <td class="p-8">
                                {% if p.status == 'submitted' %}
                                <div class="flex gap-4">
                                    <button onclick="approvePayment('{{ p.id }}','{{ p.user_id }}',{{ p.credits }})"
                                        class="btn-luxury px-6 py-2 rounded-xl text-[9px] uppercase tracking-widest">
                                        Verify
                                    </button>
                                    <button onclick="rejectPayment('{{ p.id }}')"
                                        class="bg-red-900/10 hover:bg-red-600 text-red-500 hover:text-white border border-red-900/20 px-6 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all">
                                        Dismiss
                                    </button>
                                    <button onclick="viewScreenshot('{{ p.id }}')"
                                        class="bg-white/5 hover:bg-white/10 border border-white/10 px-6 py-2 rounded-xl text-[9px] font-bold uppercase tracking-widest transition-all">
                                        Inspect
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
