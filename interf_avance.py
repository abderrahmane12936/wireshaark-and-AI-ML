import matplotlib
matplotlib.use('Agg')  # Utilisation d'un backend non-interactif pour éviter les avertissements

from flask import Flask, render_template_string, request, send_file, make_response, session, redirect, url_for, flash
import pandas as pd
import os
import matplotlib.pyplot as plt
import io
import base64
import numpy as np
import uuid
import hashlib
from functools import wraps
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib.units import inch, cm

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

# Configuration de l'utilisateur admin (unique)
ADMIN_USERNAME = "admin"
# Mot de passe hashé avec SHA-256 (le mot de passe est "admin123")
ADMIN_PASSWORD = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"

# Fonction pour vérifier si l'utilisateur est connecté
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Template HTML pour la page de connexion
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Connexion - Analyse de Sécurité Réseau</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {
            background-color: #f8f9fa;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            max-width: 400px;
            border-radius: 10px;
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            padding: 30px;
            background-color: white;
        }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .login-icon {
            font-size: 3rem;
            color: #007bff;
            margin-bottom: 15px;
        }
        .alert {
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="login-card">
                    <div class="login-header">
                        <div class="login-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <h3>Analyse de Sécurité Réseau</h3>
                        <p class="text-muted">Veuillez vous connecter pour accéder au dashboard</p>
                    </div>
                    
                    {% if error %}
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-circle me-2"></i>{{ error }}
                    </div>
                    {% endif %}
                    
                    <form method="post" action="/login">
                        <div class="mb-3">
                            <label for="username" class="form-label">Nom d'utilisateur</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-user"></i></span>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Mot de passe</label>
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-lock"></i></span>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                        </div>
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary"><i class="fas fa-sign-in-alt me-2"></i>Connexion</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

save_dir = r"C:\Users\pc\OneDrive - ISGA\Bureau\projet2K26"
output_csv = os.path.join(save_dir, "traffic_analyse.csv")

# Template HTML avec Bootstrap pour une interface plus avancée
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Analyse Avancée de Trafic Réseau</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --bg-color: #f8f9fa;
            --text-color: #212529;
            --card-bg: #ffffff;
            --attack-bg: #ffcccc;
            --normal-bg: #ccffcc;
            --header-bg: #007bff;
            --header-text: white;
            --border-color: rgba(0, 0, 0, 0.125);
            --shadow-color: rgba(0, 0, 0, 0.1);
        }
        
        [data-theme="dark"] {
            --bg-color: #212529;
            --text-color: #f8f9fa;
            --card-bg: #343a40;
            --attack-bg: #5c2d2d;
            --normal-bg: #2d5c2d;
            --header-bg: #0d6efd;
            --header-text: white;
            --border-color: rgba(255, 255, 255, 0.125);
            --shadow-color: rgba(0, 0, 0, 0.5);
        }
        
        body { 
            padding: 20px; 
            background-color: var(--bg-color);
            color: var(--text-color);
            transition: all 0.3s ease;
        }
        
        .card {
            background-color: var(--card-bg);
            border-color: var(--border-color);
        }
        
        .attack { 
            background-color: var(--attack-bg); 
        }
        .normal { 
            background-color: var(--normal-bg); 
        }
        .header { 
            background-color: var(--header-bg); 
            color: var(--header-text); 
        }
        .dashboard-card {
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s;
            margin-bottom: 20px;
        }
        .dashboard-card:hover {
            transform: translateY(-5px);
        }
        .stat-icon {
            font-size: 2.5rem;
            margin-bottom: 15px;
        }
        .chart-container {
            height: 300px;
            margin-bottom: 20px;
        }
        .table-container {
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .table-responsive {
            max-height: 500px;
            overflow-y: auto;
        }
        .navbar-brand {
            font-weight: bold;
            font-size: 1.5rem;
        }
        .nav-link {
            font-weight: 500;
        }
        .badge-attack {
            background-color: #dc3545;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
        }
        .badge-normal {
            background-color: #28a745;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
        <div class="container">
            <a class="navbar-brand" href="#"><i class="fas fa-shield-alt me-2"></i>Analyse de Sécurité Réseau</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link active" href="#"><i class="fas fa-tachometer-alt me-1"></i>Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#traffic-details"><i class="fas fa-table me-1"></i>Détails du Trafic</a>
                    </li>
                    <li class="nav-item dropdown">
                         <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                             <i class="fas fa-download me-1"></i>Télécharger
                         </a>
                         <ul class="dropdown-menu" aria-labelledby="navbarDropdown">
                             <li><a class="dropdown-item" href="/download"><i class="fas fa-file-csv me-1"></i>Format CSV</a></li>
                             <li><a class="dropdown-item" href="/download-pdf"><i class="fas fa-file-pdf me-1"></i>Format PDF</a></li>
                         </ul>
                     </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#" id="theme-toggle"><i class="fas fa-moon me-1" id="theme-icon"></i><span id="theme-text">Mode Sombre</span></a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout"><i class="fas fa-sign-out-alt me-1"></i>Déconnexion</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    <strong>Analyse complète:</strong> {{ total_count }} paquets analysés avec {{ attack_count }} attaques détectées.
                    <div class="float-end">
                    <a href="/download" class="btn btn-primary btn-sm me-2"><i class="fas fa-file-csv me-1"></i>CSV</a>
                    <a href="/download-pdf" class="btn btn-danger btn-sm"><i class="fas fa-file-pdf me-1"></i>PDF</a>
                </div>
                </div>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="card dashboard-card bg-white">
                    <div class="card-body text-center">
                        <div class="stat-icon text-success">
                            <i class="fas fa-check-circle"></i>
                        </div>
                        <h5 class="card-title">Trafic Normal</h5>
                        <h2 class="mb-0">{{ normal_count }}</h2>
                        <p class="text-muted">{{ normal_percent }}% du trafic</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card dashboard-card bg-white">
                    <div class="card-body text-center">
                        <div class="stat-icon text-danger">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <h5 class="card-title">Attaques Détectées</h5>
                        <h2 class="mb-0">{{ attack_count }}</h2>
                        <p class="text-muted">{{ attack_percent }}% du trafic</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card dashboard-card bg-white">
                    <div class="card-body text-center">
                        <div class="stat-icon text-primary">
                            <i class="fas fa-network-wired"></i>
                        </div>
                        <h5 class="card-title">Total Paquets</h5>
                        <h2 class="mb-0">{{ total_count }}</h2>
                        <p class="text-muted">Analysés avec IA</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card dashboard-card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="fas fa-chart-pie me-2"></i>Distribution du Trafic</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <img src="data:image/png;base64,{{ pie_chart }}" class="img-fluid" alt="Distribution du Trafic">
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card dashboard-card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="fas fa-chart-bar me-2"></i>Protocoles Utilisés</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <img src="data:image/png;base64,{{ protocol_chart }}" class="img-fluid" alt="Protocoles Utilisés">
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4" id="filter-section">
            <div class="col-md-12">
                <div class="card dashboard-card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="fas fa-filter me-2"></i>Filtres Avancés</h5>
                    </div>
                    <div class="card-body">
                        <form method="post" action="/" class="row g-3">
                            <div class="col-md-3">
                                <label for="protocol" class="form-label">Protocole</label>
                                <select class="form-select" id="protocol" name="protocol">
                                    <option value="all">Tous les protocoles</option>
                                    {% for protocol in protocols %}
                                    <option value="{{ protocol }}" {% if request.form.get('protocol') == protocol %}selected{% endif %}>{{ protocol }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div class="col-md-3">
                                <label for="src_ip" class="form-label">IP Source</label>
                                <select class="form-select" id="src_ip" name="src_ip">
                                    <option value="all">Toutes les IPs</option>
                                    {% for ip in src_ips %}
                                    <option value="{{ ip }}" {% if request.form.get('src_ip') == ip %}selected{% endif %}>{{ ip }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div class="col-md-3">
                                <label for="dst_ip" class="form-label">IP Destination</label>
                                <select class="form-select" id="dst_ip" name="dst_ip">
                                    <option value="all">Toutes les IPs</option>
                                    {% for ip in dst_ips %}
                                    <option value="{{ ip }}" {% if request.form.get('dst_ip') == ip %}selected{% endif %}>{{ ip }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div class="col-md-3">
                                <label for="traffic_type" class="form-label">Type de Trafic</label>
                                <select class="form-select" id="traffic_type" name="traffic_type">
                                    <option value="all" {% if request.form.get('traffic_type') == 'all' or not request.form.get('traffic_type') %}selected{% endif %}>Tout</option>
                                    <option value="normal" {% if request.form.get('traffic_type') == 'normal' %}selected{% endif %}>Normal</option>
                                    <option value="attack" {% if request.form.get('traffic_type') == 'attack' %}selected{% endif %}>Attaque</option>
                                </select>
                            </div>
                            <div class="col-12 mt-3">
                                <button type="submit" class="btn btn-primary"><i class="fas fa-search me-1"></i>Appliquer les filtres</button>
                                <a href="/" class="btn btn-secondary ms-2"><i class="fas fa-undo me-1"></i>Réinitialiser</a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4" id="traffic-details">
            <div class="col-md-12">
                <div class="card dashboard-card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="fas fa-table me-2"></i>Détails du Trafic</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-container">
                            <div class="table-responsive">
                                {{ table|safe }}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <footer class="bg-dark text-white text-center py-3 mt-5">
        <div class="container">
            <p class="mb-0">© 2025 Analyse de Sécurité Réseau - Développé pour la détection d'intrusions</p>
        </div>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Fonction pour basculer entre le mode clair et sombre
        document.addEventListener('DOMContentLoaded', function() {
            const themeToggle = document.getElementById('theme-toggle');
            const themeIcon = document.getElementById('theme-icon');
            const themeText = document.getElementById('theme-text');
            
            // Vérifier si un thème est déjà enregistré
            const currentTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', currentTheme);
            
            // Mettre à jour l'icône et le texte en fonction du thème actuel
            if (currentTheme === 'dark') {
                themeIcon.classList.remove('fa-moon');
                themeIcon.classList.add('fa-sun');
                themeText.textContent = 'Mode Clair';
            }
            
            // Ajouter un écouteur d'événement pour le bouton de basculement
            themeToggle.addEventListener('click', function(e) {
                e.preventDefault();
                
                // Basculer entre les thèmes
                const currentTheme = document.documentElement.getAttribute('data-theme');
                const newTheme = currentTheme === 'light' ? 'dark' : 'light';
                
                // Mettre à jour l'attribut data-theme
                document.documentElement.setAttribute('data-theme', newTheme);
                
                // Enregistrer le thème dans le stockage local
                localStorage.setItem('theme', newTheme);
                
                // Mettre à jour l'icône et le texte
                if (newTheme === 'dark') {
                    themeIcon.classList.remove('fa-moon');
                    themeIcon.classList.add('fa-sun');
                    themeText.textContent = 'Mode Clair';
                } else {
                    themeIcon.classList.remove('fa-sun');
                    themeIcon.classList.add('fa-moon');
                    themeText.textContent = 'Mode Sombre';
                }
            });
        });
    </script>
</body>
</html>
'''

def create_pie_chart():
    """Crée un graphique en camembert pour la distribution du trafic"""
    try:
        df = pd.read_csv(output_csv)
        attack_count = int(df[df['Prediction'] == 1].shape[0])
        normal_count = int(df[df['Prediction'] == 0].shape[0])
        
        # Créer le graphique
        plt.figure(figsize=(8, 6))
        labels = ['Trafic Normal', 'Attaques']
        sizes = [normal_count, attack_count]
        colors = ['#28a745', '#dc3545']
        explode = (0, 0.1)  # Faire ressortir les attaques
        
        plt.pie(sizes, explode=explode, labels=labels, colors=colors,
                autopct='%1.1f%%', shadow=True, startangle=140)
        plt.axis('equal')
        plt.title('Distribution du Trafic Réseau')
        
        # Convertir le graphique en image base64
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        buf.seek(0)
        plt.close()
        
        return base64.b64encode(buf.getvalue()).decode('utf-8')
    except Exception as e:
        print(f"Erreur lors de la création du graphique: {e}")
        return ""

def create_protocol_chart():
    """Crée un graphique à barres pour les protocoles utilisés"""
    try:
        df = pd.read_csv(output_csv)
        
        # Vérifier si la colonne Protocole existe
        if 'Protocole' in df.columns:
            protocol_counts = df['Protocole'].value_counts()
            
            plt.figure(figsize=(8, 6))
            bars = plt.bar(protocol_counts.index, protocol_counts.values, color='#007bff')
            
            # Ajouter les valeurs sur les barres
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                        f'{height}', ha='center', va='bottom')
            
            plt.title('Distribution des Protocoles')
            plt.xlabel('Protocole')
            plt.ylabel('Nombre de Paquets')
            plt.xticks(rotation=0)
            
            # Convertir le graphique en image base64
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight')
            buf.seek(0)
            plt.close()
            
            return base64.b64encode(buf.getvalue()).decode('utf-8')
        else:
            # Créer un graphique vide si la colonne n'existe pas
            plt.figure(figsize=(8, 6))
            plt.text(0.5, 0.5, 'Données de protocole non disponibles', 
                    horizontalalignment='center', verticalalignment='center')
            plt.axis('off')
            
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight')
            buf.seek(0)
            plt.close()
            
            return base64.b64encode(buf.getvalue()).decode('utf-8')
    except Exception as e:
        print(f"Erreur lors de la création du graphique des protocoles: {e}")
        return ""

# Routes pour l'authentification
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Vérifier les identifiants
        if username == ADMIN_USERNAME:
            # Hasher le mot de passe entré pour le comparer
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if hashed_password == ADMIN_PASSWORD:
                # Authentification réussie
                session['logged_in'] = True
                session['username'] = username
                flash('Connexion réussie!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('home'))
            else:
                error = "Mot de passe incorrect"
        else:
            error = "Nom d'utilisateur incorrect"
    
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# Protéger les routes avec login_required
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    try:
        # Charger les données
        df = pd.read_csv(output_csv)
        
        # Filtrage des données
        filtered_df = df.copy()
        
        # Récupérer les valeurs uniques pour les filtres
        protocols = sorted(df['Protocole'].unique()) if 'Protocole' in df.columns else []
        src_ips = sorted(df['IP Source'].unique()) if 'IP Source' in df.columns else []
        dst_ips = sorted(df['IP Destination'].unique()) if 'IP Destination' in df.columns else []
        
        # Appliquer les filtres si le formulaire est soumis
        if request.method == 'POST':
            # Filtrer par protocole
            if request.form.get('protocol') and request.form.get('protocol') != 'all':
                filtered_df = filtered_df[filtered_df['Protocole'] == request.form.get('protocol')]
            
            # Filtrer par IP source
            if request.form.get('src_ip') and request.form.get('src_ip') != 'all':
                filtered_df = filtered_df[filtered_df['IP Source'] == request.form.get('src_ip')]
            
            # Filtrer par IP destination
            if request.form.get('dst_ip') and request.form.get('dst_ip') != 'all':
                filtered_df = filtered_df[filtered_df['IP Destination'] == request.form.get('dst_ip')]
            
            # Filtrer par type de trafic
            if request.form.get('traffic_type'):
                if request.form.get('traffic_type') == 'attack':
                    filtered_df = filtered_df[filtered_df['Prediction'] == 1]
                elif request.form.get('traffic_type') == 'normal':
                    filtered_df = filtered_df[filtered_df['Prediction'] == 0]
        
        # Calculer les statistiques sur les données filtrées
        attack_count = int(filtered_df[filtered_df['Prediction'] == 1].shape[0])
        normal_count = int(filtered_df[filtered_df['Prediction'] == 0].shape[0])
        total_count = len(filtered_df)
        
        # Calculer les pourcentages
        attack_percent = round((attack_count / total_count) * 100 if total_count > 0 else 0, 1)
        normal_percent = round((normal_count / total_count) * 100 if total_count > 0 else 0, 1)
        
        # Ajouter des classes CSS pour colorer les lignes selon la prédiction
        def add_row_class(row):
            return 'attack' if row['Prediction'] == 1 else 'normal'
        
        # Convertir la prédiction en texte plus lisible avec badge
        def format_prediction(val):
            if val == 1:
                return '<span class="badge-attack"><i class="fas fa-exclamation-triangle me-1"></i>Attaque</span>'
            else:
                return '<span class="badge-normal"><i class="fas fa-check-circle me-1"></i>Normal</span>'
        
        # Créer une copie du DataFrame filtré pour l'affichage
        display_df = filtered_df.copy()
        
        # Formater les colonnes pour l'affichage
        if 'Prediction' in display_df.columns:
            display_df['Status'] = display_df['Prediction'].apply(format_prediction)
            display_df = display_df.drop(columns=['Prediction'])
        
        # Renommer les colonnes pour un affichage plus convivial
        column_mapping = {
            'src_ip': 'IP Source',
            'dst_ip': 'IP Destination',
            'Taille (octets)': 'Taille (octets)',
            'Protocole': 'Protocole'
        }
        display_df = display_df.rename(columns={k: v for k, v in column_mapping.items() if k in display_df.columns})
        
        # Réorganiser les colonnes pour mettre le statut à la fin
        if 'Status' in display_df.columns:
            cols = [col for col in display_df.columns if col != 'Status'] + ['Status']
            display_df = display_df[cols]
        
        # Générer le HTML avec des classes CSS pour le style
        html_table = display_df.to_html(classes='table table-striped table-hover', index=False, escape=False)
        
        # Créer les graphiques
        pie_chart = create_pie_chart()
        protocol_chart = create_protocol_chart()
        
        # Rendre le template avec les données
        return render_template_string(
            HTML_TEMPLATE,
            table=html_table,
            attack_count=attack_count,
            normal_count=normal_count,
            total_count=total_count,
            attack_percent=attack_percent,
            normal_percent=normal_percent,
            pie_chart=pie_chart,
            protocol_chart=protocol_chart,
            protocols=protocols,
            src_ips=src_ips,
            dst_ips=dst_ips
        )
    except Exception as e:
        return f'''
        <div class="container mt-5">
            <div class="alert alert-danger">
                <h3><i class="fas fa-exclamation-circle me-2"></i>Erreur lors du chargement des données</h3>
                <p>{str(e)}</p>
                <p>Vérifiez que le fichier d'analyse existe et qu'il contient des données valides.</p>
            </div>
        </div>
        '''

def generate_pdf_report(filtered_df=None):
    """Génère un rapport PDF avec les données d'analyse"""
    try:
        # Si aucun DataFrame n'est fourni, utiliser toutes les données
        if filtered_df is None:
            df = pd.read_csv(output_csv)
        else:
            df = filtered_df.copy()
            
        # Créer un buffer pour le PDF
        buffer = io.BytesIO()
        
        # Créer le document PDF
        doc = SimpleDocTemplate(buffer, pagesize=A4, title="Rapport d'Analyse de Trafic Réseau")
        styles = getSampleStyleSheet()
        elements = []
        
        # Titre du rapport
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Title'],
            fontSize=18,
            alignment=1,
            spaceAfter=12
        )
        elements.append(Paragraph("Rapport d'Analyse de Trafic Réseau", title_style))
        elements.append(Spacer(1, 0.5*cm))
        
        # Date et heure du rapport
        from datetime import datetime
        date_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        elements.append(Paragraph(f"Généré le: {date_str}", styles['Normal']))
        elements.append(Spacer(1, 0.5*cm))
        
        # Statistiques générales
        attack_count = int(df[df['Prediction'] == 1].shape[0])
        normal_count = int(df[df['Prediction'] == 0].shape[0])
        total_count = len(df)
        
        # Calculer les pourcentages
        attack_percent = round((attack_count / total_count) * 100 if total_count > 0 else 0, 1)
        normal_percent = round((normal_count / total_count) * 100 if total_count > 0 else 0, 1)
        
        # Ajouter les statistiques
        elements.append(Paragraph("Résumé des Statistiques", styles['Heading2']))
        stats_data = [
            ["Métrique", "Valeur", "Pourcentage"],
            ["Trafic Normal", str(normal_count), f"{normal_percent}%"],
            ["Attaques Détectées", str(attack_count), f"{attack_percent}%"],
            ["Total Paquets", str(total_count), "100%"]
        ]
        
        # Créer un tableau pour les statistiques
        stats_table = Table(stats_data, colWidths=[4*cm, 3*cm, 3*cm])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 1*cm))
        
        # Créer un graphique en camembert pour la distribution du trafic
        elements.append(Paragraph("Distribution du Trafic", styles['Heading2']))
        
        # Créer le graphique en camembert
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 100
        pie.height = 100
        pie.data = [normal_count, attack_count]
        pie.labels = ['Trafic Normal', 'Attaques']
        pie.slices.strokeWidth = 0.5
        pie.slices[0].fillColor = colors.green
        pie.slices[1].fillColor = colors.red
        drawing.add(pie)
        elements.append(drawing)
        elements.append(Spacer(1, 1*cm))
        
        # Ajouter un tableau des protocoles si disponible
        if 'Protocole' in df.columns:
            elements.append(Paragraph("Distribution des Protocoles", styles['Heading2']))
            protocol_counts = df['Protocole'].value_counts().reset_index()
            protocol_counts.columns = ['Protocole', 'Nombre']
            
            protocol_data = [["Protocole", "Nombre"]]
            for _, row in protocol_counts.iterrows():
                protocol_data.append([row['Protocole'], str(row['Nombre'])])
            
            protocol_table = Table(protocol_data, colWidths=[5*cm, 5*cm])
            protocol_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(protocol_table)
            elements.append(Spacer(1, 1*cm))
        
        # Ajouter un échantillon des données
        elements.append(Paragraph("Échantillon des Données (10 premières lignes)", styles['Heading2']))
        
        # Préparer les données pour le tableau
        sample_df = df.head(10).copy()
        if 'Prediction' in sample_df.columns:
            sample_df['Prediction'] = sample_df['Prediction'].apply(lambda x: 'Attaque' if x == 1 else 'Normal')
        
        # Obtenir les en-têtes et les données
        headers = list(sample_df.columns)
        data = [headers]
        for _, row in sample_df.iterrows():
            data.append([str(row[col]) for col in headers])
        
        # Créer le tableau
        sample_table = Table(data, colWidths=[2.5*cm] * len(headers))
        sample_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(sample_table)
        
        # Construire le PDF
        doc.build(elements)
        
        # Récupérer le contenu du buffer
        buffer.seek(0)
        return buffer
    except Exception as e:
        print(f"Erreur lors de la génération du PDF: {e}")
        return None

@app.route('/download')
def download():
    try:
        # Préparer le fichier pour le téléchargement
        return send_file(output_csv, 
                         mimetype='text/csv',
                         download_name='rapport_analyse_trafic.csv',
                         as_attachment=True)
    except Exception as e:
        return f'''
        <div class="container mt-5">
            <div class="alert alert-danger">
                <h3><i class="fas fa-exclamation-circle me-2"></i>Erreur lors du téléchargement</h3>
                <p>{str(e)}</p>
                <p>Vérifiez que le fichier d'analyse existe.</p>
                <a href="/" class="btn btn-primary">Retour au dashboard</a>
            </div>
        </div>
        '''

@app.route('/download-pdf')
def download_pdf():
    try:
        # Générer le rapport PDF
        pdf_buffer = generate_pdf_report()
        
        if pdf_buffer:
            # Préparer le fichier pour le téléchargement
            return send_file(
                pdf_buffer,
                mimetype='application/pdf',
                download_name='rapport_analyse_trafic.pdf',
                as_attachment=True
            )
        else:
            raise Exception("Erreur lors de la génération du PDF")
    except Exception as e:
        return f'''
        <div class="container mt-5">
            <div class="alert alert-danger">
                <h3><i class="fas fa-exclamation-circle me-2"></i>Erreur lors de la génération du PDF</h3>
                <p>{str(e)}</p>
                <a href="/" class="btn btn-primary">Retour au dashboard</a>
            </div>
        </div>
        '''

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)