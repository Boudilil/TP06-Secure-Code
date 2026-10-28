## Détection
Il faut d'abord vérifier si l'application utilise la version compromise de `requests`, je peux tout d'abord vérifier la version installée avec `pip show requests`, si la version affichée correspond à celle compromise, alors on vérifie les dépendances du projet avec `grep -n -i 'requests' requirements.txt`.


## Evaluation de l'exposition
Il faut maintenant que je vois où dans mon application le paquet `request` est utilisé, je peux alors faire la commande `grep -rn "requests" app/app.py` on obtient alors
`17:import requests`
`186:    r = requests.get(url, timeout=5, allow_redirects=False, verify=True)`
Ainsi nous savons que la route /fetch utilise `requests`.

## Confinement
On commence par arrêter immédiatement l'application avec la commande `docker stop nom-conteneur`. Ensuite, avant de modifier l'application, on garde une sauvegarde de la faille avec `docker save nom-conteneur -o nom-conteneur-incident.tar`

## Correction
On commence par exclure du requirements.in la version de `requests` qui possède des failles par une version saine on cherche un avis de sécurité s'il y en a un, le numéro de la version saine sera sûrement écrit dessus.
On régénère le fichier avec `pip-compile --upgrade-package requests --generate-hashes app/requirements.in -o app/requirements.txt` puis on reconstruit l'image sans cache et on teste le tout avec
`pip install -r app/requirements.txt`
`pytest -q tests`
`pip-audit -r app/requirements.txt`
`docker build --no-cache -t nom-image app/`
On peut alors redéployer une version saine.

## Rotation des secrets
Dans notre application, SECRET_KEY, GITHUB_TOKEN et la base de données shop.db sont à risques.
Il faudrait regénérer SECRET_KEY avec `python -c "import secrets; print(secrets.token_hex(32))"` ainsi que révoquer puis recréer GITHUB_TOKEN dans les paramètres Github.
Il faudrait aussi demander à tous les utilisateurs de changer leur mot de passe au cas où celui-ci a pu être lu dans shop.db.

## Retour d'expérience
Les versions de mes dépendances sont figées avec des hashes (`requirements.txt`). Si un paquet est modifié, pip le refuse.
Dependabot m'aurait proposé la mise à jour de `requests`.
L'appli tourne dans un conteneur avec un utilisateur non-root. Un code compromis aurait donc moins de droits.
Même après avoir appliqué toutes les corrections du TP, une faille peut toujours apparaître, par exemple dans une dépendance comme `requests`.
Il faut donc savoir réagir vite pour limiter les dégâts : repérer le problème, arrêter l'application, corriger, puis changer les secrets.