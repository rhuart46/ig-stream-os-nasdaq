import datetime
import logging
import re
import time

import requests
from trading_ig import IGService, IGStreamService
from trading_ig.config import config
from trading_ig.streamer.manager import StreamingManager

# Paramètres pour l'ordre stop
NIVEAU_DEBUT = 17800
ECART = 5
NOMBRE_NIVEAUX = 50  # Le nombre de niveaux que vous voulez
NIVEAUX_ENTREE = [NIVEAU_DEBUT + i * ECART for i in range(NOMBRE_NIVEAUX)]
SL = 30  # Stop Loss
TP = 5  # Take Profit
ACTIVATION = 5  # Activation du stop
REACTIVATION = 2  # Réactivation du stop
CONTRAT = 1  # Taille du contrat
EPIC = ["IX.D.NASDAQ.FWM2.IP"]  # Epic du produit -- bitcoin => CS.D.BITCOIN.CFD.IP -- US Tech 100 => IX.D.NASDAQ.IFE.IP
base_url = "https://demo-api.ig.com/gateway/deal/"
signal_momentum = True  # A remplacer en Prod par Signal T/F de Signal_momentum.py
signal_volume = True  # A remplacer en Prod par Signal T/F du Signal_volume.py

ordres_crees = {niveau: False for niveau in NIVEAUX_ENTREE}
print("=============")
print("Initialisation des dictionnaires :")
print("ordres_crees :   ", ordres_crees)
TP_atteints = {niveau: False for niveau in NIVEAUX_ENTREE}
print("TP_atteints :   ", TP_atteints)
seuil_reactivation = {niveau: False for niveau in NIVEAUX_ENTREE}
print("Seuil Reactivation :   ", seuil_reactivation)
deal_ids = {niveau: None for niveau in NIVEAUX_ENTREE}
print("deal_ids :   ", deal_ids)
print("=============")
ordres_ouverts = {niveau: False for niveau in NIVEAUX_ENTREE}
print("ordres ouvert :   ", ordres_ouverts)
print("=============")


def authentifier():
    start_time = time.time()  # Début du timing
    headers = {
        "Content-Type": "application/json",
        "X-IG-API-KEY": config.api_key,
        "Accept": "application/json; charset=UTF-8",
        "IG-ACCOUNT-ID": config.acc_number,
    }
    auth_data = {"identifier": config.username, "password": config.password}
    auth_response = requests.post(f"{base_url}/session", headers=headers, json=auth_data)
    if auth_response.status_code == 200:
        headers["X-SECURITY-TOKEN"] = auth_response.headers["X-SECURITY-TOKEN"]
        headers["CST"] = auth_response.headers["CST"]
        return headers
    else:
        print("Erreur de connexion.")
        exit()
    end_time = time.time()  # Fin du timing
    print(f"Temps d'exécution de Authentifier: {end_time - start_time} secondes")


def verifier_niveaux_occupes(base_url, NIVEAUX_ENTREE):
    start_time = time.time()  # Début du timing
    # Authentification
    auth_data = {"identifier": config.username, "password": config.password}
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "X-IG-API-KEY": config.api_key,
        "Accept": "application/json; charset=UTF-8",
        "IG-ACCOUNT-ID": config.acc_number,
        "Version": "2",
    }
    auth_response = requests.post(f"{base_url}/session", headers=headers, json=auth_data)
    # print(auth_response.status_code)
    if auth_response.status_code == 200:
        headers["X-SECURITY-TOKEN"] = auth_response.headers["X-SECURITY-TOKEN"]
        headers["CST"] = auth_response.headers["CST"]
        # Récupération des activités depuis l'API
        activity_url = f"{base_url}/history/activity?from=2023-02-05T00:00:00&pageSize=500"
        activity_response = requests.get(activity_url, headers=headers)

        ordres_crees = {niveau: False for niveau in NIVEAUX_ENTREE}
        ordres_ouverts = {niveau: False for niveau in NIVEAUX_ENTREE}
        deal_ids = {niveau: None for niveau in NIVEAUX_ENTREE}
        etat_des_numeros = {}

        if activity_response.status_code == 200:
            data = activity_response.json()["activities"]
            # Analyser les données
            for row in data:
                match = re.search(r"\b[A-Z0-9]{8}\b", row["result"])
                if match:
                    numero_unique = match.group()
                    etat_des_numeros[numero_unique] = None

            for numero in etat_des_numeros:
                for row in reversed(data):
                    if numero in row["result"]:
                        if "fermée(s)" in row["result"] or "supprimé" in row["result"]:
                            etat_des_numeros[numero] = "fermé"
                            break
                        elif "ouvert:" in row["result"]:
                            etat_des_numeros[numero] = "ouvert"
                        elif "exécuté:" in row["result"]:
                            etat_des_numeros[numero] = "exécuté"

            for row in data:
                niveau = float(row["level"])
                match = re.search(r"\b[A-Z0-9]{8}\b", row["result"])
                if match:
                    numero_unique = match.group()
                    if niveau in NIVEAUX_ENTREE and etat_des_numeros.get(numero_unique) == "ouvert":
                        ordres_crees[niveau] = True
                        deal_ids[niveau] = row["dealId"]
                    if niveau in NIVEAUX_ENTREE and etat_des_numeros.get(numero_unique) == "exécuté":
                        ordres_ouverts[niveau] = True
                        deal_ids[niveau] = row["dealId"]

            return ordres_crees, deal_ids, ordres_ouverts
        else:
            print("Erreur lors de la récupération des données de l'activité.")
            return None
    end_time = time.time()  # Fin du timing
    print(f"Temps d'exécution de Verifier_Niveaux_Occupés: {end_time - start_time} secondes")


# On LANCE DIRECTEMENT la fonction pour vérifier et mettre à jour les DICTIONNAIRES
# ===============================================================================
ordres_crees, deal_ids, ordres_ouverts = verifier_niveaux_occupes(base_url, NIVEAUX_ENTREE)

for niveau in NIVEAUX_ENTREE:
    if ordres_crees[niveau] and not ordres_ouverts[niveau]:
        print(f"Niveau {niveau} est en attente par l'ordre {deal_ids[niveau]}")
    elif ordres_ouverts[niveau]:
        print(f"Niveau {niveau} est ouvert par l'ordre {deal_ids[niveau]}")
    else:
        print(f"Niveau {niveau} est libre.")
# ===============================================================================

print("=============")
print("Initialisation des dictionnaires :")
print("ordres_crees :   ", ordres_crees)
print("TP_atteints :   ", TP_atteints)
print("deal_ids :   ", deal_ids)
print("seuil_reactivation :  ", seuil_reactivation)
print("ordres_ouverts :   ", ordres_ouverts)


def recuperation_detail_epic(epic):
    # Authentification
    auth_data = {"identifier": config.username, "password": config.password}
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "X-IG-API-KEY": config.api_key,
        "Accept": "application/json; charset=UTF-8",
        "IG-ACCOUNT-ID": config.acc_number,
        "Version": "2",
    }
    auth_response = requests.post(f"{base_url}/session", headers=headers, json=auth_data)
    if auth_response.status_code != 200:
        return "Erreur de connexion."

    headers["X-SECURITY-TOKEN"] = auth_response.headers["X-SECURITY-TOKEN"]
    headers["CST"] = auth_response.headers["CST"]

    # Récupération des détails du marché
    market_details_response = requests.get(f"{base_url}/markets/{epic}", headers=headers)
    if market_details_response.status_code == 200:
        market_details = market_details_response.json()
        expiry = market_details["instrument"]["expiry"]
        return expiry
    else:
        return "Erreur lors de la récupération des détails du marché."


# Utilisation de la fonction pour récupérer la date d'expiration de l'EPIC
expiry = recuperation_detail_epic("IX.D.NASDAQ.FWM2.IP")
print(f"Expiry: {expiry}")


def creer_ordre_stop(epic, ENTREE, headers):
    start_time = time.time()  # Début du timing
    order_data = {
        "epic": epic,
        "expiry": expiry,
        "direction": "BUY",
        "size": str(CONTRAT),
        "level": str(ENTREE),
        "forceOpen": True,
        "type": "STOP",
        "currencyCode": "USD",
        "timeInForce": "GOOD_TILL_CANCELLED",
        "stopDistance": str(SL),
        "limitDistance": str(TP),
        "guaranteedStop": True,
    }
    order_response = requests.post(f"{base_url}workingorders/otc", headers=headers, json=order_data)
    if order_response.status_code == 200:
        print(
            f"Ordre placé sur {epic} avec succès au niveau {ENTREE} pour un stop loss de {SL} et un take profit de {TP}"
        )
        deal_reference = order_response.json()["dealReference"]
        deal_id = recuperer_deal_id(deal_reference, headers)  # Appel de la fonction pour récupérer le dealId
        if deal_id:
            print(f"Ordre placé sur {epic} avec succès. Deal ID: {deal_id}")
            deal_ids[ENTREE] = deal_id  # Après avoir reçu le deal_id de l'API
            # print(f"dealId pour le niveau {ENTREE} est maintenant: {deal_ids[ENTREE]}")
            for niveau, d_id in deal_ids.items():
                if d_id:
                    print(f"Niveau: {niveau}, dealId: {d_id}")
            return deal_id
        else:
            print("Erreur lors de la récupération du dealId")

    else:
        print("Erreur lors du placement de l'ordre.")
        print(order_response.json())
        return None

    end_time = time.time()  # Fin du timing
    print(f"Temps d'exécution de Creer_OS: {end_time - start_time} secondes")


def recuperer_deal_id(deal_reference, headers):
    start_time = time.time()  # Début du timing
    """headers = {
        'Content-Type': 'application/json',
        'X-IG-API-KEY': config.api_key,
        'Accept': 'application/json; charset=UTF-8',
        'IG-ACCOUNT-ID': config.acc_number,
        'VERSION': '1'  # Spécification de la version de l'API
    }"""
    activity_url = f"{base_url}/confirms/{deal_reference}"
    print(activity_url)
    activity_response = requests.get(activity_url, headers=headers)
    if activity_response.status_code == 200:
        deal_id = activity_response.json().get("dealId")
        return deal_id
    else:
        print("Erreur lors de la récupération du dealId")
        return None

    end_time = time.time()  # Fin du timing
    print(f"Temps d'exécution de Recuperer_DealID: {end_time - start_time} secondes")


def verifier_etat_ordre(deal_id, headers, base_url):
    url = f"{base_url}/workingorders/"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        order_info = response.json()
        print(f"order_info: {order_info}")
        # Parcourir tous les ordres de travail
        for working_order in order_info["workingOrders"]:
            if "workingOrderData" in working_order and working_order["workingOrderData"]["dealId"] == deal_id:
                print(f"Niveau de l'ordre {deal_id}: {working_order['workingOrderData']['level']}")
                # Vous pouvez ajouter plus de logique ici pour vérifier l'état spécifique de l'ordre
                return working_order["workingOrderData"]
    else:
        print(f"Erreur lors de la vérification de l'ordre: {response.text}")
        return None


def supprimer_ordre(niveau):
    start_time = time.time()  # Début du timing
    deal_id = deal_ids[niveau]
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "X-IG-API-KEY": config.api_key,
        "Accept": "application/json; charset=UTF-8",
        "IG-ACCOUNT-ID": config.acc_number,
        "Version": "2",
    }
    print(f"deal_id dans la fonction supprimer_ordre est: {deal_id}")

    if not ("X-SECURITY-TOKEN" in headers and "CST" in headers):
        # Si les tokens ne sont pas dans les headers, on fait une nouvelle authentification
        auth_data = {"identifier": config.username, "password": config.password}
        auth_response = requests.post(f"{base_url}/session", headers=headers, json=auth_data)

        if auth_response.status_code == 200:
            headers["X-SECURITY-TOKEN"] = auth_response.headers["X-SECURITY-TOKEN"]
            headers["CST"] = auth_response.headers["CST"]
        else:
            logging.error(f"Échec de la nouvelle authentification: {auth_response.text}")
            return

    if deal_id:
        delete_url = f"{base_url}workingorders/otc/{deal_id}"
        delete_response = requests.delete(delete_url, headers=headers)

        if delete_response.status_code == 200:
            logging.info(f"Ordre {deal_id} supprimé pour le niveau {niveau}.")
            deal_ids[niveau] = None
        else:
            logging.error(f"Erreur suppression ordre {deal_id}: {delete_response.text}")
    else:
        logging.info(f"Aucun ordre actif pour le niveau {niveau}.")

    end_time = time.time()  # Fin du timing
    print(f"Temps d'exécution de Supprimer_OS: {end_time - start_time} secondes")


# test fonction suppresion du Working Order (pas encore ouvert, car sinon c'est suppression de /positions/otc)
# supprimer_ordre(17970)


def attendre_confirmation_ordre(deal_id, headers, timeout=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        if verifier_etat_ordre(deal_id, headers, base_url):
            return True
        time.sleep(0.5)
    return False


def validation_ordre(ticker, headers):
    start_time = time.time()  # Début du timing
    global ordres_crees, TP_atteints, deal_ids, seuil_reactivation, ordres_ouverts

    for ENTREE in NIVEAUX_ENTREE:

        # Suppression de l'OS si le prix est en dessous de l'entrée - activation
        if ticker.offer < ENTREE - ACTIVATION and ordres_crees[ENTREE] and not ordres_ouverts[ENTREE]:
            # if not verifier_etat_ordre(deal_ids[ENTREE]):
            supprimer_ordre(ENTREE)
            # print(supprimer_ordre(ENTREE))
            ordres_crees[ENTREE] = False
            logging.info(f"ordres_crees[{ENTREE}] réinitialisé (FALSE) = {ordres_crees[ENTREE]}")
            # TP_atteints[ENTREE] = False
            deal_ids[ENTREE] = None
            logging.info(f"deal_ids[{ENTREE}] réinitialisé (NONE) = {deal_ids[ENTREE]}")

        # Vérifier si le prix est passé en dessous de ENTREE - REACTIVATION
        if ticker.offer < ENTREE - REACTIVATION:
            seuil_reactivation[ENTREE] = True
            TP_atteints[ENTREE] = False

        # Création de l'OS si le prix est au-dessus de l'entrée + activation et seuil reactivation est atteint
        if (
            seuil_reactivation[ENTREE]
            and not ordres_ouverts[ENTREE]
            and not ordres_crees[ENTREE]
            and signal_volume == True
            and signal_momentum == True
        ):
            if (
                deal_ids[ENTREE] is None or deal_ids[ENTREE] == ""
            ) and ENTREE - ACTIVATION <= ticker.offer <= ENTREE + ACTIVATION:
                deal_id = creer_ordre_stop(ticker.epic, ENTREE, headers)
                if deal_id:
                    if attendre_confirmation_ordre(deal_id, headers):
                        ordres_crees[ENTREE] = True
                        deal_ids[ENTREE] = deal_id
                        logging.info(
                            f"ordres_crees[{ENTREE}] = {ordres_crees[ENTREE]} avec deal_ids[{ENTREE}] = {deal_ids[ENTREE]}"
                        )
                    else:
                        print(f"Erreur : ordre non confirmé pour le niveau {ENTREE}")
                    # ordres_crees[ENTREE] = True
                    # print(f"ordres_crees[{ENTREE}] = {ordres_crees[ENTREE]}")
                    # deal_ids[ENTREE] = deal_id
                    # print(f"deal_ids[{ENTREE}] = {deal_ids[ENTREE]}")

        # On met à jour le dictionnaire ordres_ouverts si l'ordre est ouvert
        if ordres_crees[ENTREE] and deal_ids[ENTREE] and ticker.offer > ENTREE and not ordres_ouverts[ENTREE]:
            ordres_ouverts[ENTREE] = True
            logging.info(f"ordres_ouverts[{ENTREE}] = {ordres_ouverts[ENTREE]}")

        # Réactivation de l'OS si le prix est au-dessus de l'entrée + TP
        if ticker.offer > ENTREE + TP and ordres_ouverts[ENTREE] and not TP_atteints[ENTREE]:
            TP_atteints[ENTREE] = True
            ordres_crees[ENTREE] = False
            ordres_ouverts[ENTREE] = False
            deal_ids[ENTREE] = None
            seuil_reactivation[ENTREE] = False
            logging.info(f"TP atteints[{ENTREE}] = {ENTREE + TP}")

    end_time = time.time()  # Fin du timing
    print(f"Temps d'exécution de validation_ordre: {end_time - start_time} secondes")


def est_token_expire(derniere_authentification):
    maintenant = datetime.datetime.now()
    # Calcule la différence en secondes
    difference = (maintenant - derniere_authentification).total_seconds()
    # 6 heures = 21600 secondes
    return difference >= 21600


def main():
    logging.basicConfig(level=logging.INFO)
    ig_service = IGService(
        config.username,
        config.password,
        config.api_key,
        config.acc_type,  # DEMO
        acc_number=config.acc_number,  # ZG9AS
    )

    derniere_authentification = datetime.datetime.now()
    headers = authentifier()
    # verifier_et_maj_ordres_existants(headers)

    ig = IGStreamService(ig_service)
    ig.create_session(version="2")
    sm = StreamingManager(ig)

    crypto_epics = EPIC

    tickers = []
    for epic in crypto_epics:
        sm.start_tick_subscription(epic)
        tickers.append(sm.ticker(epic))

    while True:
        if est_token_expire(derniere_authentification):
            print("Token expiré, reconnexion en cours...")
            headers = authentifier()
            print(headers)
            derniere_authentification = datetime.datetime.now()
            print("Reconnecté avec succès")

        for ticker in tickers:
            for ENTREE in NIVEAUX_ENTREE:
                """difference = ticker.offer - ENTREE
                if difference > 0:
                    print(f"Le prix (offer) de {ticker.epic} est au-dessus de {ENTREE} de {abs(difference):.2f} points")
                else:
                    print(f"Le prix (offer) de {ticker.epic} est en dessous de {ENTREE} de {abs(difference):.2f} points")
                """
                # Récupération de la date et de l'heure actuelles
                maintenant = datetime.datetime.now()
                # Formatage de la date et de l'heure
                date_heure_formattee = maintenant.strftime("%Y-%m-%d %H:%M:%S")
                print(f"=====  {ticker.epic}====== {ticker.offer}")
                print(f"Date et heure actuelles: {date_heure_formattee}")
                validation_ordre(ticker, headers)
                time.sleep(2)

    sm.stop_subscriptions()


if __name__ == "__main__":
    main()
