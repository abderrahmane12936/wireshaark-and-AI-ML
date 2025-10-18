#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import pandas as pd
import joblib
from scapy.all import rdpcap, IP

# Chemins des fichiers
save_dir = r"C:\Users\pc\OneDrive - ISGA\Bureau\projet2K26"
model_path = os.path.join(save_dir, "model_rf.pkl")
output_csv = os.path.join(save_dir, "traffic_analyse.csv")

def convert_pcap_to_csv(pcap_file, csv_file):
    """Convertit un fichier PCAP en CSV"""
    print(f"Lecture du fichier PCAP: {pcap_file}")
    
    try:
        # Lecture du fichier pcap avec scapy
        packets = rdpcap(pcap_file)
        
        with open(csv_file, 'w', newline='') as file:
            # Créer un DataFrame vide
            data = []
            
            count = 0
            for pkt in packets:
                try:
                    if IP in pkt:
                        # Déterminer le protocole de la couche supérieure
                        if pkt.haslayer('TCP'):
                            protocol = 'TCP'
                        elif pkt.haslayer('UDP'):
                            protocol = 'UDP'
                        elif pkt.haslayer('ICMP'):
                            protocol = 'ICMP'
                        else:
                            protocol = 'Other'
                        
                        # Ajouter les données au DataFrame
                        data.append({
                            'src_ip': pkt[IP].src,
                            'dst_ip': pkt[IP].dst,
                            'protocol': protocol,
                            'length': len(pkt)
                        })
                        count += 1
                except Exception as e:
                    print(f"Erreur avec un paquet: {e}")
                    continue
            
            # Créer le DataFrame et sauvegarder en CSV
            df = pd.DataFrame(data)
            df.to_csv(csv_file, index=False)
            print(f"✅ {count} paquets exportés vers CSV: {csv_file}")
            return True
    except Exception as e:
        print(f"❌ Erreur lors de la lecture du fichier PCAP: {e}")
        print("Vérifiez que le fichier existe et qu'il est au format pcap/pcapng valide.")
        return False

def generate_example_data():
    """Génère des données d'exemple pour démonstration"""
    print("Génération de données d'exemple pour démonstration...")
    
    # Créer des données d'exemple avec les colonnes du modèle
    # Obtenir les noms de colonnes du modèle
    model = joblib.load(model_path)
    feature_names = model.feature_names_in_
    
    # Créer un DataFrame vide avec les bonnes colonnes
    df = pd.DataFrame(columns=feature_names)
    
    # Remplir avec des données aléatoires
    num_samples = 20
    for i in range(num_samples):
        # Créer une ligne avec des valeurs par défaut à 0
        row = {col: 0 for col in feature_names}
        
        # Modifier quelques valeurs pour simuler du trafic
        if i < 15:  # Trafic normal
            row['Flow Duration'] = 100 + (i * 50)
            row['Flow Packets/s'] = 5 + (i % 10)
            row['Flow Bytes/s'] = 500 + (i * 100)
        else:  # Attaques
            row['Flow Duration'] = 1000 + (i * 200)
            row['Flow Packets/s'] = 50 + (i % 20)
            row['Flow Bytes/s'] = 5000 + (i * 1000)
            
        # Ajouter la ligne au DataFrame
        df.loc[i] = row
    
    # Ajouter les colonnes src_ip et dst_ip pour l'affichage
    df['src_ip'] = ['192.168.1.' + str(10 + i) if i < 15 else '45.33.' + str(i-14) + '.' + str(100+i) for i in range(num_samples)]
    df['dst_ip'] = ['10.0.0.' + str(1 + (i % 5)) if i < 15 else '192.168.1.1' for i in range(num_samples)]
    
    return df

def analyze_traffic(csv_file):
    """Analyse le trafic avec le modèle ML"""
    print(f"Analyse du fichier CSV: {csv_file}")
    
    try:
        # Vérifier si le fichier CSV existe et n'est pas vide
        if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
            try:
                # Charger le trafic
                traffic = pd.read_csv(csv_file)
                
                if len(traffic) == 0:
                    print("Le fichier CSV est vide. Utilisation de données d'exemple...")
                    traffic = generate_example_data()
            except Exception as e:
                print(f"Erreur lors de la lecture du CSV: {e}")
                print("Utilisation de données d'exemple...")
                traffic = generate_example_data()
        else:
            print("Le fichier CSV est vide ou n'existe pas. Utilisation de données d'exemple...")
            traffic = generate_example_data()
        
        # Charger le modèle
        model = joblib.load(model_path)
        
        # Adapter colonnes pour la prédiction
        try:
            # Conserver les colonnes src_ip et dst_ip pour l'affichage
            display_cols = ['src_ip', 'dst_ip']
            display_data = traffic[display_cols].copy() if all(col in traffic.columns for col in display_cols) else pd.DataFrame({'src_ip': [], 'dst_ip': []})
            
            # Préparer les caractéristiques pour le modèle
            # Utiliser les caractéristiques attendues par le modèle
            expected_features = model.feature_names_in_
            
            # Créer un DataFrame avec les caractéristiques attendues, initialisées à 0
            features_df = pd.DataFrame(0, index=range(len(traffic)), columns=expected_features)
            
            # Ajouter des caractéristiques basiques basées sur les données disponibles
            if 'protocol' in traffic.columns:
                # Encoder le protocole
                protocol_mapping = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'Other': 0}
                traffic['protocol_encoded'] = traffic['protocol'].map(protocol_mapping).fillna(0)
                
                # Définir quelques caractéristiques basées sur le protocole
                if 'Protocol' in expected_features:
                    features_df['Protocol'] = traffic['protocol_encoded']
            
            if 'length' in traffic.columns:
                # Utiliser la longueur du paquet pour certaines caractéristiques
                if 'Flow Bytes/s' in expected_features:
                    features_df['Flow Bytes/s'] = traffic['length'] * 10  # Simulation
                if 'Flow Packets/s' in expected_features:
                    features_df['Flow Packets/s'] = 1  # 1 paquet par flux
                if 'Flow Duration' in expected_features:
                    features_df['Flow Duration'] = traffic['length'] * 2  # Simulation
            
            # Faire la prédiction avec les caractéristiques préparées
            predictions = model.predict(features_df)
            
            # Ajouter les prédictions aux données d'affichage
            display_data['Prediction'] = predictions
            
            # Ajouter des informations supplémentaires pour l'affichage
            if 'length' in traffic.columns:
                display_data['Taille (octets)'] = traffic['length']
            if 'protocol' in traffic.columns:
                display_data['Protocole'] = traffic['protocol']
            
            # Compter les attaques
            attack_count = int(sum(predictions))
            print(f"Résultats: {attack_count} attaques détectées sur {len(traffic)} paquets")
            
            # Sauvegarder les résultats
            display_data.to_csv(output_csv, index=False)
            print(f"✅ Analyse enregistrée: {output_csv}")
        except Exception as e:
            print(f"Erreur lors de la prédiction: {e}")
            # Créer un DataFrame minimal avec les prédictions à 0
            display_data = traffic[['src_ip', 'dst_ip']].copy() if all(col in traffic.columns for col in ['src_ip', 'dst_ip']) else pd.DataFrame({'src_ip': [], 'dst_ip': []})
            display_data['Prediction'] = 0
            if 'length' in traffic.columns:
                display_data['Taille (octets)'] = traffic['length']
            if 'protocol' in traffic.columns:
                display_data['Protocole'] = traffic['protocol']
            display_data.to_csv(output_csv, index=False)
        
        # Indiquer comment visualiser les résultats
        print("\nVous pouvez visualiser les résultats dans l'interface web: http://127.0.0.1:5000")
        print("Si l'interface n'est pas déjà lancée, exécutez: python interf.py")
        return True
    except Exception as e:
        print(f"❌ Erreur lors de l'analyse: {e}")
        return False

def main():
    """Fonction principale"""
    # Vérifier les arguments
    if len(sys.argv) < 2:
        print("Usage: python analyse_pcap.py <chemin_fichier_pcap>")
        print("Exemple: python analyse_pcap.py capture.pcapng")
        return
    
    # Récupérer le chemin du fichier PCAP
    pcap_file = sys.argv[1]
    
    # Vérifier si le fichier existe
    if not os.path.exists(pcap_file):
        print(f"❌ Le fichier {pcap_file} n'existe pas.")
        return
    
    # Définir le chemin du fichier CSV
    csv_file = os.path.join(save_dir, "traffic.csv")
    
    # Convertir le fichier PCAP en CSV
    if convert_pcap_to_csv(pcap_file, csv_file):
        # Analyser le trafic
        analyze_traffic(csv_file)

if __name__ == "__main__":
    main()