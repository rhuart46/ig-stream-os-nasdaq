# Installation

### Pré-requis

* Python ([installation](https://www.python.org/downloads/))
* git ([installation](https://git-scm.com/download)) ([première configuration](https://git-scm.com/book/fr/v2/Personnalisation-de-Git-Configuration-de-Git))
* pyenv (recommandé) ([installation](https://github.com/pyenv/pyenv?tab=readme-ov-file#installation))

### Cloner le projet

1. Ouvrir un terminal et se placer dans un répertoire qui sera le parent du code téléchargé.
2. Exécuter la commande : `git clone https://github.com/rhuart46/ig-stream-os-nasdaq.git`
3. Un répertoire a été créé portant le même nom que le repo git, se déplacer à l'intérieur.

### Installer les dépendances (dans un environnement géré par pyenv)

1. Créer un environnement virtuel : `pyenv virtualenv <nom_environnement>`
2. Lier cet environnement au répertoire courant : `pyenv local <nom_environnement>`
3. Installer les dépendances : `python -m pip install -r requirements.txt`

# Lancement

Editer le fichier `trading_ig_config_sample.py` pour y écrire des informations de connexion valides
et le renommer `trading_ig_config.py`.

Puis exécuter la commande :
```shell
nohup python stream_os_nasdaq.py &
```
