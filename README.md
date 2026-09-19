# talk

> **Chat chiffré de bout en bout, proche de Discord** — sujet d'examen `SDV DEV 2026`.

Application de messagerie où les utilisateurs s'authentifient, rejoignent des salons et échangent des messages **sans que le serveur puisse jamais lire le contenu en clair** (chiffrement de bout en bout côté client).

## Énoncé & notation

L'énoncé complet et la grille de notation (sur 20) sont disponibles dans **[`EXAMEN.md`](./EXAMEN.md)** :

- stack imposée : **Python + FastAPI** · **Redis** ou **MongoDB** · **HTML/CSS/JS vanilla**
- exigences fonctionnelles, de sécurité (**security by design**) et de qualité
- organisation sur le dépôt (branches, CI), livrables
- grille détaillée sur 20 pts et seuil de validation (**12/20**)

## Mode de travail sur ce dépôt

- Travail **individuel** : chaque étudiant développe son projet sur **sa propre branche**.
- Nommage de branche recommandé : `etudiant/<nom>-<prenom>`.
- **Ne jamais casser les branches des autres** (pas de force-push, reset, réécriture ou suppression des branches d'autrui).
- La branche `main` sert de référence (énoncé) ; les projets sont rendus sur les branches étudiantes avec **CI verte**.

## Démarrage rapide (attendu dans les projets rendus)

Chaque branche étudiante doit fournir un projet **dockerisé** :

```bash
docker compose up          # lance l'application (app + Redis/MongoDB)
docker compose run --rm test   # lance la suite de tests (unitaires + intégration)
```

La **CI GitHub Actions** exécute les tests et le linter à chaque push / pull request.

## Structure attendue d'une branche étudiante

```
Dockerfile                # image de l'application
docker-compose.yml        # app + base de données
.github/workflows/*.yml   # pipeline CI (tests + linter)
app/                      # backend FastAPI
frontend/                 # HTML/CSS/JS vanilla + chiffrement côté client
tests/                    # tests unitaires + intégration / non-régression
README.md                 # documentation personnelle (fonctionnement, sécurité, mise en place)
```

## Ressources

- Dépôt : <https://github.com/DevsAreAlsoHumans/talk>
- Énoncé & grille : [`EXAMEN.md`](./EXAMEN.md)

---

*Projet pédagogique — année 2026.*